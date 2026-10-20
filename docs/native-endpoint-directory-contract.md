# Explicit native Endpoint registration and Owner directory

Contract revision: `native-endpoint-directory-v1`. Account and Node wire remain
1, Client contract remains `client-hub-v1.6.5` with 55 operations, topology
projection remains version 2, and the Hub schema is unchanged. This additive
contract reuses Endpoint/Principal, Node PQ binding, N2 provenance, N3 read cache
and the original Pair/Fabric authorization paths. It does not activate the
separate installation-registration H1 proposal or create installation identities.

## Current Thread and zero-rights registration

The user explicitly joins the **current native Thread**. The trusted Node
adapter must obtain its actual calling context and verify the native record and
canonical cwd. A startup SID environment variable cannot establish a new or
forked Thread's identity. Hub authenticates the currently Owner-approved Node,
not a cryptographic proof supplied by Codex for its native SID. No process or
historical-thread scan enrolls additional Threads.

The existing `/v2/node/control/rpc` carrier adds these typed operations:

| Operation | Request | Result |
|---|---|---|
| `node.endpoint.register` | `harness,native_session_id,name,workspace` | `endpoint_id,name,workspace,presence,reused,state_digest` |
| `node.endpoint.leave` | `harness,native_session_id,state_digest` | The same self-state result, with `presence=left` after success |
| `node.native_pair.available` | `{}` | `pairs:[{pair_id,label,join_until,slots:[{slot,generation}]}],truncated` |

All requests are strict JSON inside the original signed/encrypted Node packet.
Owner, Node, credentials and PQ epochs are derived from the current binding,
never accepted as body selectors. Names are nonempty UTF-8, at most 256 bytes;
workspaces are nonempty UTF-8, at most 4096 bytes. Harness/SID are at most 64/256
bytes. Control characters and noncanonical surrounding whitespace are refused.
Node paths are opaque to the Hub OS and are not turned into public aliases.

Registration inserts only an agent Principal and private Endpoint, with no Group,
Network membership, SessionBinding, access lease, history, key, role grant or
communication permission. Initial `presence=offline` does not claim a live
native writer. The existing pending-Group migration marker is only a retained
storage coordinate, not a business authorization state.

An existing `(harness,native_session_id)` retains its actual Principal, Owner,
Node, name and workspace. Other Owner/Node adoption is refused. A changed cwd
returns `ENDPOINT_STATE_CONFLICT`; a different proposed name returns the original
name. This version has no rename operation. Repeat registration never renews a
lease, restores a revoked edge or revives `left` state.

`state_digest` is an opaque SHA-256 CAS coordinate, not a capability. It includes
the original Endpoint coordinates/state; Group state, version, revision and
context policy; Network state/version; membership and Endpoint-edge revisions;
and binding/access identities, epochs and states. It excludes heartbeat,
last_seen, update timestamps and lease-expiry refreshes. Leave compares it under
the SQLite writer and rechecks the **current** credential/Owner/device/key/PQ
binding independently. A mismatch refuses all effects. Success uses the same
transactional all-scope withdrawal as Fabric Leave: revoke this Endpoint's Group
edges, Network edges, access sessions and native SessionBindings, advancing their
real revisions/epochs. Other Endpoints and Principal-level Network memberships
are retained. Neither Thread nor workspace is deleted.

Hub Nodes retains its two-request bounded admission capacity. Capacity exhaustion
returns HTTP `429` with `Retry-After: 1`, separately from authentication/context
rejection (`403`); it creates no unbounded queue. The sender retains and retries
the **same original sealed packet**. A busy delivery is not settlement of an
original packet already submitted by another concurrent attempt, and is never
permission to change its operation ID, digest, counter or target.

Known terminal errors use the existing encrypted wrapper:
`{ok:false,operation_id,sequence,error_code}` with exactly
`ENDPOINT_CONTEXT_INVALID`, `ENDPOINT_STATE_CONFLICT` or
`ENDPOINT_NOT_FOUND_OR_NOT_AUTHORIZED`. No raw SID/path is echoed. Unknown
mutation/sealing/storage outcomes remain `OUTCOME_UNCERTAIN`. The original
Node inbox, response retention and permanent sequence highwater govern exact
retries; a retry never redispatches an admitted mutation. Registration is
idempotent and can safely read the retained identity with a new request when
reconciliation is necessary. An uncertain Leave must be reconciled against
current self-state; it must not be guessed successful or replaced with a new
identity. This is not an atomic claim that business commit and response sealing
cannot be separated by process failure.

## Reuse of the existing Pair consent path

Pair discovery returns only current Owner-created, Owner-committed Pairs for
this exact Node and current PQ/Owner/account provenance. Expired Pairs and those
without an available RESERVED slot are filtered before the 64-Pair SQL bound.
The list never returns session tokens, private keys, native SID or workspace.
It is a bounded snapshot: `truncated=true` cannot establish uniqueness. The
adapter displays labels and slot choices; multiple candidates or duplicate
labels require selection. It must not choose the first/latest Pair or silently
switch a slot after response loss.

The live Thread still performs the original `node.native_pair.describe` and
`node.native_pair.join`, with the original bootstrap-proof digest, generation,
native record/cwd check and durable original-request reconciliation. Only a
private, offline, entirely unadmitted registration with exactly the same
Owner/Node/runtime/SID/cwd may reuse its Endpoint and Principal. Any membership,
Endpoint edge, binding, access session, key candidate or Pair-slot history,
including revoked history, prevents that reuse. Original name and identities
are preserved. This does not give an App permission to fabricate a native writer.

Both existing exact Owner Pair consents and actual endpoint-key signatures
remain mandatory for communication. Topology regroup delegation and Link review
policy do not delegate endpoint-key signing. App closure/uninstall is not an
implicit communication revocation; accepted original authority remains bounded
by its real deadline and revocation rules.

## Private Owner read for a finite Cicada App

An account login alone grants no Root or directory permission. The old N2
`ActivationAllowedOperations()` remains exactly `nodes.list,session.capabilities`.
It does not permit `topology.snapshot`. The new bounded read is separate:

* Operation `owner.endpoints.read`, POST `/v2/owner/endpoints/read`.
* GET the **same path** before starting/signing/persisting a new read. Its public
  `cicada.owner-endpoints-capabilities.v1` response contains contract revision,
  availability, exact Hub ID/fingerprint and the fixed 64-row/48-KiB/60-second
  bounds. `ParseOwnerEndpointReadCapabilities(raw, trustedHub)` validates it with
  a 4-KiB limit. Old Hub 404, an old/invalid format, another Hub or unavailable
  mode prevents new read creation. This does not extend the old strict N3
  capabilities object. Public availability is neither authorization nor a
  settlement of an existing pending request; old pending reads retain their
  exact original packet and authenticated reconciliation rules.
* `OwnerEndpointReadRequest`: `format=cicada.owner-endpoints-read.v1`, the existing
  `AppNodeRequestContext`, current `session_token` and independent `owner_proof`.
* `OwnerEndpointReadClaims`: `purpose=OWNER_ENDPOINT_DIRECTORY_READ`, full original
  `OwnerAppNodeScope`, full current `OwnerAppNodeBinding` as `node`, original
  `request_id`, nonce, cursor, limit, issued_at and expires_at. Signature domain
  is `cicada/owner/endpoint-directory-read/v1\x00`. The existing ML-DSA signer and
  proof validation primitives are reused with this distinct purpose/domain.
* Limit is 1..64. Each page requires a new, explicitly approved Owner signature.
  The App can describe it as “read this Node's own Threads”; no per-row approval
  is required. A different Owner key, device key alone, changed request/nonce,
  Node, epoch, cursor, limit or expired proof cannot authorize the page.

All timestamps are canonical UTC instants. Proof lifetime is at most 60 seconds,
no later than the actual account session expiry, with at most 30 seconds future
clock skew. The server samples actual current time after acquiring the SQLite writer, so a request waiting for that lock cannot keep its pre-wait TTL. It verifies the signed/encrypted
App packet, current login, Owner/key/device/Node and exact original N2 completed
provenance and ACTIVE lease row, including unchanged identity epochs/tuple, in
one writer snapshot before reading. Like N3's independent Owner purposes, the
old N2 operation TTL expiring does not forbid this **new** signed purpose. It
does not renew the old N2 expiry, open topology or restore `nodes.list` authority.
Revoked provenance or any current identity/key binding denies even cached paths.

The result format is `cicada.owner-endpoints-result.v1`:
`request_id,request_packet_digest,hub_id,owner_id,device_id,node_id,state,captured_at,
freshness,endpoints,next_cursor`. Cards contain only
`endpoint_id,name,workspace,harness,presence` for this actual Owner and selected
Node. Presence is `offline`, `left`, `LEASE_RECENT` or `UNKNOWN`; a stored online
label without a current lease is not reported as current online evidence.
`freshness=SNAPSHOT_ONLY` is mandatory. Stable Endpoint-ID ordering and Owner/Node
filtering precede LIMIT. A cursor outside the selected Owner/Node is refused.
The next cursor is the last actually returned row. The complete JSON result is
at most 48 KiB, including cursor reserve, so long paths can reduce page size
without exceeding the existing account PQ packet budget.

Use `NewOwnerEndpointRead(...)` and `VerifyOwnerEndpointReadResult(...)` in
`internal/hubaccountwire/owner_endpoint_read.go`. Client verification binds the
original packet, signed scope, ID order, state, finite request window and page
cursor. A result is never a communication capability or proof of later authority.

The existing N3 128-entry/five-minute per-device read cache stores exact sealed
receipts. Directory receipts remain protected from capacity eviction for
90 seconds, covering their entire possible fresh-proof window including skew.
A full protected cache applies temporary backpressure; it is not a lifetime
128-request quota. Expired/unprotected entries can be reclaimed. An exact cached
receipt remains its original snapshot; after eviction/expiry an old proof can
only receive `READ_EXPIRED` with no cards, never a fresh read. Read cache state
creates no identity, grant, lease renewal, key approval or business mutation.

## Existing management and peer directories

Already authorized encrypted `topology.snapshot` remains a separate management
operation. Its existing Endpoint cards add own `workspace`; the query now includes
private unadmitted Endpoints and reports `endpoints_truncated` at 1000 rows. SQL
checks Endpoint **and** Principal Owner before LIMIT; current accepted-request,
device/key/account-lease guards are retained. The whole topology remains explicitly
`best_effort`, not a global transactional revision or a complete listing when a
truncation flag is true. A finite App cannot use this extension to bypass its
existing management denial.

Network administration does not make a person Owner of foreign Endpoints.
`network.directory` continues returning only its approved scoped alias/minimal
card. Group List/Resolve likewise redact foreign raw names, workspace, Node
locators, harness/capability/tag and binding data, including ambiguity candidates
and errors. Since Group has no separate approved alias field, its existing
authorized opaque Endpoint ID is used for a foreign card; cross-Owner human
aliases remain in the existing opt-in Network directory. Hidden names/Node/path
filters cannot resolve a foreign Endpoint. Same-Owner resolution applies both
Node and workspace constraints, including direct-ID and Pair paths. Authorized
duplicate names still yield `AMBIGUOUS`; no partial or first-row result is chosen.

## Validation boundary

Implementation and exact source/artifact evidence belong in
`native-endpoint-directory-validation.md`. Synthetic tests and disposable TCP
prove only their recorded scopes. They do not establish Codex per-call context,
native Runtime consumption, Windows GUI/DPAPI/ACL, Android, physical devices,
public HTTPS, a resident deployment upgrade or new Owner→Node key-signing
delegation. Those remain separately attributed.


## Node-operator self-inventory profile

`node-operator-v1` adds only `node.endpoints.list` to the existing Node PQ
carrier. Its request is `{cursor?,limit?,harness?,native_session_id?}`: limit is
1..64 (default 64); harness and SID must be supplied together for exact self
lookup, with no cursor and limit 1. It never creates an Endpoint. Its result is
`{node_id,captured_at,freshness:SNAPSHOT_ONLY,endpoints,next_cursor}`; cards are
`endpoint_id,name,workspace,harness,native_session_id,presence,state_digest`.
Owner and current Node are derived from the approved PQ binding, both Endpoint
and Principal Owner are checked before LIMIT, and a foreign cursor is refused.
The complete result, including next_cursor, is at most 48 KiB. A long-path page
ends at the last actually returned ID.

This is the local Node operator's private registered metadata, not an Endpoint
business directory. It is available through the existing OS UID/private IPC
boundary for an explicit operator command. Models' MCP `members/find` operations
retain their original Group authorization; no Node credential, SID roster or
state digest is delegated to those model tools. The App's independent Owner
read continues omitting native SID and state_digest.

GET `/v2/owner/endpoints/read?profile=node-operator` returns the public
`cicada.node-operator-capabilities.v1` format: contract revision, availability,
Hub ID, **Node-Control** fingerprint, four Node operation IDs and page bounds.
The adapter validates this small response against its existing approved Node
binding using `nodewire.ParseNodeOperatorCapabilities`, before starting any new
pending operation. Old Hub/old format, wrong pin or unavailable profile refuses
new starts; it cannot settle an old pending request. Empty-query GET keeps the
original Owner capabilities format unchanged. This adds no new service, Owner
signature delegation, business role or permission.

## Local Node adapter and exact intents

The existing same-UID private Unix socket accepts Version 1 operations
`endpoint_register`, `endpoint_leave`, `endpoint_directory`,
`native_pair_available`, and `native_pair_join_named`. Their local request is
`{version,operation,request_id,issued_at,api_origin,harness?,native_session_id?,
workspace?,name?,pair_label?,slot?,cursor?,limit?}`. This is a local adapter DTO,
not a replacement Hub protocol. The operator-only directory accepts cursor and
limit, without a caller-selected native identity. Register/Leave/Join independently
check the original local Codex record and canonical workspace. No identity is
created to make that check pass.

`newLocalEndpointRequestID(now)` produces 12 lowercase hex Unix-millisecond
digits followed by 20 random hex digits. The prefix must equal the UTC
`issued_at` millisecond. New intents allow a two-minute window and at most
30 seconds future skew. Request ID, full original intent digest, Hub, Node,
operation and outcome state bind the response. Changing any intent field with
the same ID is refused. Availability is checked before preparing a new intent;
an old pending packet remains recoverable independently of current availability.

The existing private 8 MiB Node-Control state stores original intent metadata,
fixed child operation IDs, prepared bodies and bounded original sealed receipts.
Receipt retention and clearing the shared outbox use one durable write, including
startup recovery. There is a 1 MiB completion reserve before a new local packet
is sent, and a 256 KiB local receipt ceiling. At most 256 mutation intents and
64 read intents are active. Expired settled/no-dispatch intents can be collected
with a monotonically increasing `local_endpoint_admission_floor_ms` in the same
write; new admissions at or below that floor are refused even after clock
rollback. Pending/unknown packets are never evicted. Capacity applies temporary
backpressure; it is not a Node lifetime quota or a reason to replace keys.

After the issue window, only an already sealed original packet may be retried;
no new child read or mutation is prepared. Leave first performs a fixed exact
self lookup, never a registration probe, then durably fixes its original state
digest. Lost replies cannot cause a new read to withdraw scopes joined later.
Named Join requires exactly one matching human Pair label and explicit A/B
slot in a complete available result. Pair ID/generation are saved once; original
Describe, Owner-key trust, bootstrap proof, Join, key approval and dual consent
remain authoritative. No first-row selection or App-prebound slot is introduced.

## Local per-call Codex context

`codex_context_issue` accepts Version 1, API origin, harness `codex`, native SID,
canonical workspace, transcript path, 64-hex MCP connection nonce, tool name,
64-hex canonical business-argument digest, turn ID and tool-use ID.
`codex_context_consume` accepts Version 1, API origin, connection nonce, tool
name, argument digest and opaque ticket; it has no caller-supplied SID or path.
The consumed result contains only the verified original context and expiry.

The Node reads one supplied transcript under its actual Codex sessions root,
checking non-link path components, same-UID non-writable record ownership,
regular-file open-handle identity and bounded `session_meta` metadata. It does
not scan session history per tool call. Metadata ID and cwd must match exactly;
fork ancestry never supplies an identity. Supported sources are the existing
`cli` shape and the isolated-tested `exec`/`codex_exec` shape. Missing/unknown
sources and structured subagent records are unsupported.

The Node uses a memory-only random HMAC key and at most 512 live opaque tickets,
each expiring in 30 seconds. Tickets bind the current Hub/Node binding, API
origin, actual SID/cwd, MCP nonce, tool, argument digest, turn and call. Valid
consumption is atomic and single-use; mismatch does not consume a valid ticket.
Live tickets are never evicted for capacity. Node restart invalidates all tickets;
an MCP restart uses a new nonce. No key is written to disk or supplied to a model.
This establishes only the existing same-UID local trust boundary. It is not a
Codex signature, proof of human intent, or protection from a malicious process
under the same UID. Inherited parent context without a distinct native record
cannot be promoted into a proven child identity. Real per-call Hook/MCP Runtime,
TUI/desktop, Windows IPC and subagent lifecycle coverage remain separately
attributed and are not established by these deterministic tests.
