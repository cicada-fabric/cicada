# Explicit native Endpoint registration and Owner directory

Contract revision: `native-endpoint-directory-v1`. Account and Node wire remain
1, Client contract remains `client-hub-v1.6.5` with 55 operations, topology
projection remains version 2, and the Hub schema is unchanged. This additive
contract reuses Endpoint/Principal, Node PQ binding, N2 provenance, N3 read cache
and the original Pair/Fabric authorization paths. It does not activate the
separate installation-registration H1 proposal or create installation identities.

## MCP contact selection

The additive local MCP tool `cicada_select_peer` accepts the closed object
`{scope:"group"|"network",network_id?,query?}`. Group means the current selected
joined Group; it cannot select another Group by model-supplied ID. Network
requires one explicit, already joined Network. Unknown scopes, caller identity,
credential paths and foreign fields reject. The optional UTF-8 query is at most
128 bytes and matches only permitted directory fields: visible name, Endpoint
ID and, for Group cards, already-visible Node/workspace. It never queries an
Owner inventory or implicitly joins, grants access, registers a Thread or
starts a Node.

The tool reads the existing Hub-authorized Group or Network directory without
a default filter to the caller's Node. It uses the real `{endpoints:[...]}`
directory response, bounded to the first 64 rows; filtering this page does not
prove that an absent match is absent from the whole directory. Results explicitly
report `directory_bounded:true` and `directory_may_have_more:true`. A form is
offered only when the Host explicitly negotiated `elicitation.form` during MCP
initialization. Unsupported Hosts refuse before directory reads or Network
recovery. The transport owns form I/O, cancellation, decline and timeouts; it
does not supply a Cicada actor or authorize sending.

The form says “Choose a contact”. Labels lead with the permitted name and
visible Node/workspace, a short disambiguating suffix and optional snapshot
status. Display text is UTF-8 safely bounded; it does not change original names
or paths. Foreign Group cards retain their existing redaction, with no hidden
Node, workspace, capability or binding fields restored. Foreign cards without
a public alias show a neutral contact label. Network cards retain only the
existing nickname/Endpoint/availability projection. The full Endpoint ID stays
in the internal mapping and result, not a user copy/paste workflow. Host-owned
presentation and color are outside this interface.

The returned form values are random opaque option IDs mapped privately to exact
directory entries. Accepting a label, a guessed value or an unoffered option is
invalid. After acceptance, the business layer rechecks the original native
Thread, selected Hub/Node, authenticated source, scope and directory lookup by
the original exact Endpoint ID. Changed source or visible target binding
ID/epoch, expiry, revocation and lost visibility reject; it never resolves a
similar label as a replacement. A Network directory provides no target binding
revision: none is invented. The current Node peer-key and Hub send Guards
remain authoritative at transmission time.

Success returns `peer_selection_id,scope,scope_id,endpoint_id,binding_id,
binding_epoch,expires_at,freshness` plus the bounded-directory indicators.
`freshness` is `SNAPSHOT_ONLY`; empty binding/zero epoch mean the public card
did not provide those coordinates. References live only in the original MCP
process, expire 120 seconds after the snapshot, and are capped at 64 live
selections. Decline, unsupported form, invalid response, expired/stale selection
and cancellation observed before the local reference commit create no reference
or peer message. The final insertion is serialized with cancellation and checks
the snapshot deadline again after any Hub wait. A later cancellation does not
undo an already committed read-only reference; it never sends a message. A selection is
neither a capability nor proof of human approval for any later action.

`cicada_send` and `cicada_ask` accept `peer_selection_id` instead of `target`,
`link_id`, `network_id` or `data_scope`; mixing even empty competing selectors
rejects. The original tool name/arguments, including this reference, are
verified by the normal fresh Hook ticket before business code derives the
exact internal destination. The ticket is not reused after changing model
arguments. Each later send/ask requires its own current native proof and
current authorization. For visible Group binding coordinates, the immutable
outbox and private Node request also carry the expected target binding/epoch;
the Node checks them against current peer-key evidence before sealing. An old
strict Node that does not understand those additive private fields refuses.
Frozen Hub/Client wire identifiers and versions are unchanged.

An authorized minimal foreign Group card may pass only its accepted exact
Endpoint ID to the existing private Node peer-key path, without borrowing a
capability or disclosing private fields to the MCP caller. Plain model target
or alias calls do not receive this exception. Source authorization and current
bilateral Node/Hub Guards still apply. A visible contact does not imply
permission to send, ask, execute, delegate or create membership.

The existing durable MCP outbox records the reference and digest of the
original business intent together with its exact resolved destination. An
explicit identical idempotency-key retry may recover only that original outcome,
including after selection expiry or MCP process restart; it does not need a new
form and does not create or resend an operation. Changed intent or native scope
rejects. Actual pending/uncertain transmission uses the existing explicit
operation-retry path and retains the original IDs, ciphertext and current Guard
requirements. An expired or missing reference cannot create new work.

### Existing Network sessions on a selected Node

The formal installed-Node path keeps its guard against arbitrary environment
configuration. The narrow trusted adapter obtains its private directory from
the original discovery pin:
`dirname(mcp_session_state_file)/network-session/scopes/<original-scope-hash>/`.
The existing `<network_id>.session.json` must be same-user `0600` in private
`0700` directories, without symlinks. Strict fields must match the original
origin, selected Node, runtime, native Thread, workspace and explicit Network.
No model argument or `CICADA_NETWORK_SESSION_DIR` selects this installed path.
Legacy explicit configurations retain their original separate configuration
rules. The actual Network `whoami` response has only
`network_id,endpoint_id,principal_id`; its private source snapshot additionally
binds the original token digest and trusted local coordinates, without returning
the token or inventing a wire binding/version field.

The current Group token is first tried as a read-only exact Network credential.
Pair and local-domain access can share that original token/epoch with a Group
lease. Their existing empty Network discovery grants refuse discovery; contact
selection does not increase them. Such shared access is never independently
renewed. Store rejects independent renewal in the same transaction before any
rotation if a Group binding shares its credential/lease, or a current/historical
Pair slot or local-domain member owns that access ID. The original heartbeat,
credential, key, epoch and Group policy remain intact.

Only explicitly selecting a Network may recover a missing local token through
the existing Node `network_renew` operation. The source Endpoint comes from the
current authenticated self, or, for Network-only Threads with no Group, the
Node's existing independent enrollment history. That exact read uses the
current WriterScope/account digest, runtime/native identity digest, Hub,
Network, `group_id=''` and `DISTINCT endpoint_id LIMIT 2`; absent or ambiguous
history refuses. It does not enumerate other Threads, touch history timestamps
or promote historical observations to authority. The Node verifies the real
native record/cwd and the Hub repeats its current Node/Owner/key, membership,
Endpoint-edge and access-session Guards. No registration, invitation or grant
is created by recovery.

Recovery serializes the selected scope and Network and syncs a credential-free
`<network_id>.renew-pending.json` intent before its one renewal request. At most
64 Network namespaces may acquire session/lock/pending files per native scope;
a saturated scope refuses new names while preserving existing sessions and
uncertain records. There is no deletion of unknown outcomes to make room.
The returned nonempty token and exact original Endpoint/Node/native/Hub/Network
are checked before private persistence. A known renewed token returned with a
post-renew native-binding failure is retained, with
`NETWORK_NATIVE_BINDING_PENDING`; no form or send proceeds. A truly missing or
unknown response leaves `NETWORK_RENEW_UNCERTAIN`. Later calls never silently
rotate another epoch. The pre-existing renewal route has no exact-operation
receipt: automatic settlement of that unknown renewal is unavailable, and this
adapter deliberately retains evidence for explicit recovery instead of making
up a token or claiming success.

Hub Nodes composes only the existing exact Network paths and methods needed
for this flow: GET `whoami,directory`, POST `resolve`, POST
`direct/native-binding,peer-key,key-candidate,request-cancel`, GET
`direct/request-status` under `/v2/fabric/networks/<id>/`; POST
`/v2/fabric/node/networks/renew`; and POST
`send,ask,reply,claim,authorize,receipt,reply-route` under
`/v2/fabric/node/networks/direct/`. Each reaches the original Fabric handler and
its current authentication/authorization; route availability grants no caller
rights. There is no generic prefix forwarding. Wrong methods, extra segments,
Join, invitations/admin, Task/Broadcast and collaboration-key routes remain
closed in this bounded mode. Authentication remains independent of Control.

2026-10-25 producer validation used dirty parent
`ebc71dbfe72d0a9fe7aa657a0c69cfafea9f10f2`; the 1,580 Go/module inputs hashed
to `86c49901ee88123590a7f33e7b1e2602d921535361a3cc56f3aaa0310c500825`.
Isolated related CLI tests recorded 26 pass/0 fail/0 skip; four core-package
lanes recorded 11 pass/0 fail/0 skip. Ten bounded race processes recorded 18
passing test events, including parent/subtest events, with no failure or skip.
Five-package vet and Linux/Windows CGO0 CLI builds exited 0. Source manifests
were unchanged during these checks; this paragraph was added afterward without
changing tested Go inputs.

The real default Hub Nodes fixture uses independent Owner-signed Network
registrations on two distinct logical Nodes, original Hook proofs, a real MCP
form, production source-Node sealing, Hub admission and receiver-side
authorization/decryption. Network-only missing-token recovery, committed-renewal
response loss, retained known token after native-binding failure, current target
revocation, cancelled final Hub check, exact original outcome recovery and
shared Pair/domain heartbeat preservation have separate targeted tests. Native
records and the recipient fixture are synthetic; real Codex/physical Runtime,
actual App, physical second Node, public HTTPS and Docker integration remain
separate QA scopes. Minimal foreign-card routing has a synthetic private-Node
boundary test plus the existing backend redaction regression; a full selected
send across different Owners is **NOT_RUN** here.

Receipts and exact logs are protected under
`~/Cicada/.local/evidence/peer-selection-hub-20261025/`.
`receipt.json` deliberately retains the initial related-CLI FAIL: an existing
local-domain test assumes empty process Thread environment variables. Restoring
all changed Go files to the parent blobs reproduced that same failure in
`baseline-context-environment-2.log`. `isolated-normal-receipt.json` records the
same CLI suite with only the test subprocess's `CODEX_THREAD_ID` and
`CODEX_SESSION_ID` explicitly empty; the user's environment was not changed.
Earlier diagnostic/fixture failures are also retained and are not passes.
Automatic exact settlement of an unknown legacy Network renewal remains
unavailable as described above. No existing user identity, credential, Node,
resident service, deployment or login policy was changed by this validation.

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

The five existing MCP directory tools accept only their advertised query fields:
`cicada_members` has `status,node_id,harness,limit`; `cicada_list` additionally
has the existing `machine_id` compatibility filter; `cicada_find`,
`cicada_resolve` and `cicada_inspect` have `query,node_id,workspace`. These are
target filters within the authenticated caller's current Group, never caller
identity claims. String properties retain their original values, including
empty strings, in the Hook argument digest and consumed MCP call; the existing
business handler still trims query/filter text. `limit` must be an integer.
Null and wrong property types refuse. Unknown properties and caller identity or
credential fields refuse even when null or empty. Other MCP tools retain their
existing identity-field prohibition; no generic identity exception is added.

Hub Nodes mode also serves the existing exact POST aliases
`/v2/fabric/find` and `/v2/fabric/inspect` alongside `/v2/fabric/resolve` through
the same Group session authentication, native-collaboration self guard, bounded
ResolveInput decoder, `Fabric.Resolve` authorization and privacy projection.
MCP retains each original HTTP alias. The two GET list aliases retain their
existing implementation. Incorrect methods and extra path segments refuse;
there is no general Fabric prefix, new permission, DTO or wire-version change.

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
`cli` shape, the isolated-tested `exec`/`codex_exec` shape, and exactly
`source=vscode` with `originator=codex-tui`. The last combination was observed
in an actual Codex 0.163.0 TUI after its shared daemon was initialized through
`--remote`; it does not establish arbitrary VSCode/IDE source support. Other
`vscode` originators, missing/unknown sources and structured subagent records
remain unsupported. This source compatibility changes none of the original
SID/session ID, cwd, ownership, non-writable mode, inode, configured record-root,
ticket or current authorization checks.

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

## Operator command client persistence

The consumer uses `openCodexOperatorIntent(path)` with the existing selected
MCP session-state root and `scopes/<mcpSessionScope>/operator-intent.json`.
It retains legacy/component overrides; the helper neither discovers SID nor
parses prompts. The path is absolute and protected through existing App-path,
private directory, atomic secret-file and existing cross-process flock
primitives. One scope has one pending command and one bounded last-ack marker;
there is no new service, queue, dependency or MCP session schema.

`prepare(q,nodeID)` persists the original full request before IPC and returns it.
With an existing pending command, matching full command semantics and Node
always reuse the original ID/time, including when the caller supplied a new
candidate ID. A different API, Node, SID, cwd, operation or business argument
cannot overwrite it. The recommended template leaves ID/time empty so the
shared time-bound factory runs once at initial preparation.

`call(socketPath,q,nodeID)` performs preparation and validates the returned
request ID, complete original digest, Node, Hub, operation and expected result
shape. The digest binds API/SID/cwd and all business arguments. A completed Join
also requires its original SID/cwd/Node, Endpoint/Group/Principal, binding/epoch
and nonempty local session credential. Only complete success or a known
operation-specific terminal refusal is saved as an acknowledgeable result.
Unknown replies, missing credentials, arbitrary errors and mismatched replies
leave the original pending intact. Received Join credentials remain private;
the cached result proves its recorded completion, not a fresh current lease.

The consumer first persists a Join in the existing MCP session store, or emits
the verified non-Join output, then explicitly calls `ack(requestID,digest)`.
Acknowledgment is an atomic compare-and-swap and requires the retained verified
result. Its own repeated acknowledgment is idempotent; an old acknowledgment
cannot delete a later pending command. Process restart, IPC response loss and
local result-save failure preserve the original request. Current server Guard,
native-scope and lease checks continue to govern use of a restored session.

## Node-managed explicit Pair leases

Only `native_pair_join_named` may enroll a managed lease. The Node first durably
reserves one of 32 live entries and 16 KiB of completion space per RESERVED entry
in its existing bounded Node-Control file, before issuing the immutable Join.
All writers preserve that completion headroom. The entry binds the original
intent/digest, Join operation ID/body, slot/generation, proof digest, current
Hub/Node binding, original accepted policy and independently installed Owner
public pin/version. The complete authenticated original Join reply is frozen
by digest; its session token remains in the original sealed receipt, not a new
plaintext token store. ACTIVE is persisted only after the existing current
Guard/native-scope/key-publication completion checks, before IPC success.

The states are RESERVED, ACTIVE and STOPPED. Uncertain RESERVED entries never
expire into replacement authority. Restart resumes only explicitly enrolled
ACTIVE entries with an unchanged original tuple and a still-live last proven
lease; it never discovers historical receipts, an MCP cache, a last SID or a
replacement slot to construct new authority. Leave, explicit revocation,
changed epochs/policy/Owner pin, the last proven lease deadline or the original
peer ceiling permanently stop that entry. A delayed heartbeat cannot reactivate
a concurrently stopped entry. Known STOPPED history may be collected after its
peer ceiling (or the original intent TTL for proven no-effect records), together
with the existing monotonic admission floor. This is a live-capacity limit,
not a lifetime quota. Unknown outcomes are retained.

One worker belongs to the existing Node bridge context/wait group and closes
with it. It issues only the existing session-authenticated Fabric heartbeat,
independently of model inference or a first MCP tool call. It neither Joins,
generates identities/consent nor periodically runs the Join completion pipeline.
It processes at most four ACTIVE entries per 30-second round, with a five-second
request budget per entry and a wake after explicit activation. At full capacity,
the normal round-robin budget is 32/4*30+4*5=260 seconds within the five-minute
lease; outages, process suspension and unavailable authorization storage are not
promises of continued availability. With up to four entries the scheduled Node
cost is two heartbeats/minute/entry, in addition to the existing MCP heartbeat
when running. No new ownership handoff or daemon is introduced. Each batch
merges current state under the shared lock and persists at most once; an equal
or older successful expiry causes no write. Concurrent outbox/counter work is
preserved. Presence means recent lease renewal, not proof that a human/native
Thread is online or has consumed a message.

Every renewal checks the original signed Describe/Join, local policy and Owner
pin through the existing Nodekeys services. `OpenExistingCryptoState(ctx,dir)`
opens only an existing real private 0700 directory/0600 database and private
sidecars, reads live WAL with `mode=rw` plus `query_only`, and requires the current
schema. It does not create directories/databases/keys, repair permissions or
migrate. Existing-only reads have a SQLite busy wait of at most 100 ms, shortened
by the caller deadline; the normal writer/outbox configuration is unchanged.
Missing policy/pin, a revoked pin or a definite authority/integrity mismatch stops
the entry. A missing database path is unavailable storage, not proof that its authorization
rows were revoked. That and other unproven I/O/busy/deadline errors send no heartbeat
and retain the original entry for retry within its last proven lease. No fresh authority is
inferred from an unavailable store. The offline immutable trust snapshot reader
is not used for this online path.

A known local pre-Join rejection (capacity or unavailable/ambiguous/truncated
selection, changed generation, or an expired pre-dispatch preparation) is an
acknowledgeable REFUSED result only after the bound original intent proves all
three dispatch coordinates absent: neither the shared pending operation ID nor
its decoded packet route names the Join (malformed pending packets cannot prove
absence), there is no native-Pair sealed receipt, and no local Join step has a
request packet, response packet or settled flag. The Node persists an original
`local_join_refused` fence before returning the existing recognized named-Join
terminal error. This local authentication/no-dispatch evidence is not a newly
signed Hub refusal; the existing Hub-signed refusal path remains separate.
No client error whitelist or public wire identifier changes. Any dispatched or
uncertain old/upgraded intent remains UNKNOWN, including one missing the new
managed marker. After a consumer emits the refusal and ACKs it, a repaired
capacity/directory permits only a fresh explicit command: the old raw request
cannot Join. Failure to persist the fence remains UNKNOWN.

These optional private fields extend Node state Version 1 directionally. The
new binary reads earlier state; an older strict reader may reject a state after
these fields are written. Preserve it and its identities; automatic downgrade,
state replacement and renewal of old non-enrolled sessions are not supported.
The frozen public protocol, App/MCP/main implementations and consent powers are
unchanged by this checkpoint.

## Installed local Node discovery v1

The installation sequence is file installation, an explicit user start of the
existing Node Agent, then normal Codex plugin installation/trust. The installer
materializes one plugin bundle with an absolute installed executable and explicit
user root. Neither installation nor plugin loading starts/enrolls a Node, joins
a Thread, grants authority, or changes existing keys/state. An installed plugin
must not depend on a previously started Codex daemon's PATH or Cicada environment.

Only `machine agent --user-root ABS` enables publication. Without this explicit
flag, old Agent launches and low-level bridge fixtures publish nothing and do
not inspect a discovery HOME. `--once` does not publish. An explicit `--state-dir`
or existing component override retains precedence; otherwise this mode uses
`<selectedRoot>/state` with the existing original-state guard. No state migration
is performed. Single-Hub publication requires both `--mcp-session-state-file ABS`
and `--mcp-outbox-state-file ABS` explicitly; these declare two independent original
paths, without creating/opening their data. Existing custom paths must be selected,
not replaced by empty paths under a new root. Multi-Hub publication uses each
original resolved per-Hub `mcp/sessions.json` and `mcp/outbox.sqlite3`, rejects those
two single-Hub flags, and preserves the original shared WriterRoot.

Each Agent publishes one same-UID locator under `<root>/run/nodes/`. The filename
is lowercase SHA-256 of `cicada/local-node-locator/v1`, NUL, canonical absolute
per-Hub StateDir, NUL, NodeID, followed by `.json`. The bounded strict JSON has
exact fields `format` (`cicada.local-node-locator.v1`), `instance_id` (16 random
bytes in lowercase hex), and `socket_path`. It contains no bearer, SID, workspace,
Owner proof or private key. The instance is a process label, not a new identity.
The selected existing root remains same-UID owned and protected against group/
world writes, including an existing 0755 root; its permissions are not repaired.
Only the new `run`/`nodes` directories require 0700 and locators require 0600.
Readers reject symlink ancestors,
wrong ownership/permissions, nonregular files, duplicate/unknown JSON fields,
trailing data and a changed open-handle identity. Publication is atomic and only
after the existing private socket is listening. An existing target must itself
strictly match this locator format and derived socket; unknown private bytes
are retained rather than overwritten. Close removes only its own exact
locator instance/inode; crashes may retain stale locators. Readers never clean,
repair, migrate or create anything.

On the original socket, `local_node_describe` accepts exactly Version 1,
`operation`, `nonce` (32 random bytes in lowercase hex), `instance_id`, and
`locator_digest` (SHA-256 of the complete original locator bytes). The Node checks
its own published instance and retained locator digest rather than blindly echoing
them. `localJoinResponse.node_description` contains `nonce`, `instance_id`,
`locator_digest`, and `connection` (the stable pin below). It uses only the Agent's
existing approved in-memory Node-Control binding and pinned context. An unapproved
or unavailable binding returns NODE_NOT_READY. This operation makes no Hub/Control
request, opens/creates no database/key, and changes no counter/outbox. Nonce and
same-UID socket checks establish only fresh local discovery, not human intent,
a Hub/Owner signature, business permission or protection from a hostile same-UID
process. All existing context tickets and current server/Node Guards remain required.

The shared Go API is:

```go
type LocalNodeSelection struct { UserRoot, HubID, NodeID string }
// Binding contains the complete original public Node-Control coordinates.
type LocalNodeBinding struct {
    BindingID string
    BindingVersion, NodeKeyEpoch, NodeKeyVersion, HubKeyVersion uint64
    NodeKeyID, NodeKeyFingerprint, HubKeyID, HubFingerprint string
}
type LocalNodeConnectionPin struct {
    UserRoot, HubID, APIOrigin, NodeID, SocketPath string
    StateDir, WriterRoot, MCPSessionStateFile, MCPOutboxStateFile string
    Binding LocalNodeBinding
    HubTransportDescriptor, HubDialAddress string // optional native TLS metadata
}
type LocalNodeConnection struct {
    Pin LocalNodeConnectionPin
    InstanceID, LocatorDigest string
}
func ResolveLocalNodeConnection(context.Context, LocalNodeSelection,
    *LocalNodeConnectionPin) (LocalNodeConnection, error)
```

JSON pin fields use their snake_case names; `binding` contains `binding_id`,
`binding_version`, `node_key_epoch`, `node_key_version`, `hub_key_version`,
`node_key_id`, `node_key_fingerprint`, `hub_key_id`, and `hub_fingerprint`.
Both full fingerprints reuse `nodewire.IdentityFingerprint`; no truncated ID or
new fingerprint algorithm replaces them. Optional native TLS fields are
`hub_transport_descriptor` and `hub_dial_address`; both are absent in legacy
JSON, and must be present together for native TLS. The exact signed descriptor
matches Hub ID, origin and the approved Node-Control public binding. All stable
coordinates/paths are pinned. A newly live-verified instance may change after
restart. For an unchanged exact native descriptor and every other original pin
field, only its canonical numeric dial address may also change, following the
Agent's explicit verified relocation. Original persisted pins and pending
packets retain their bytes; legacy/native mode, CA, epoch and authority changes
remain refused. See the [native TLS contract](hub-native-tls-contract.md#node-persistence-readiness-and-selected-consumers).
The resolver checks
the nonce, instance, root, original locator digest, derived filename/socket path,
normalized origin and complete binding. With an existing pin it addresses only
that original locator and rejects any changed stable coordinate or path.

One resolution has a single context budget of at most three seconds, shortened
by its parent deadline; it is not a fresh timeout per candidate. Limits are 64
locator entries, 4 KiB per locator, 1 KiB describe request, 96 KiB pin JSON and
97 KiB complete describe response,
4096 UTF-8 bytes per path and 256 bytes per identifier. The resolver searches
only the selected root, never other roots, process lists, historical SIDs or
recent files. No live match returns `ErrLocalNodeNotRunning`/NODE_NOT_RUNNING;
multiple matches return `ErrLocalNodeSelectionAmbiguous`/NODE_SELECTION_AMBIGUOUS.
Only definite ENOENT/connection-refused socket outcomes count as stale. Invalid
format/ownership/permission/path/response returns `ErrLocalNodeDiscoveryInvalid`/
LOCAL_NODE_DISCOVERY_INVALID; uncertain I/O or the global deadline returns
`ErrLocalNodeDiscoveryUnavailable`/LOCAL_NODE_DISCOVERY_UNAVAILABLE. A bad or
uncertain candidate cannot be skipped to guess another Node. Other fixed errors
are `ErrLocalNodeNotReady`/NODE_NOT_READY, `ErrLocalNodeDiscoveryLimit`/
LOCAL_NODE_DISCOVERY_LIMIT, `ErrLocalNodeBindingChanged`/LOCAL_NODE_BINDING_CHANGED,
and `ErrLocalNodeConfigRequired`/LOCAL_NODE_CONFIG_REQUIRED. Discovery is local
availability metadata, never a public Hub capability or caller authorization.

The existing operator helper adds `prepareForConnection(q,connection)` and
`callForConnection(q,connection)` while preserving explicit legacy methods. New
pending commands atomically retain an optional `connection_pin` in the original
private intent file. Exact retries require the same complete stable pin, origin,
Node and command; restart instance changes do not rewrite authority. A new root
mode encountering old pending material without a pin returns CONFIG_REQUIRED,
retains its bytes and cannot ACK, silently attach current authority or create a
side database to hide it. Its original explicit legacy recovery remains separate.
Changed binding or cache paths cannot retarget an uncertain pending operation.
No public Hub wire/catalog identifier changes in this checkpoint.

This installed discovery checkpoint supports the standard HTTPS/application-PQ
profile only. A Node with a selected strict-PQTLS runtime/transport returns
CONFIG_REQUIRED through Describe/Resolve; its existing business service and
original explicit strict flow remain unchanged. A missing Codex-daemon PQTLS
environment variable can never turn that Node into a standard transport. No
transport-profile field or new strict-runtime implementation is introduced.

The installed consumer uses `mcp --codex-context --user-root ABS` and
`codex-hook --user-root ABS`, optionally selecting exact `--hub-id`/`--node-id`.
It rejects mixed legacy API/Endpoint/registry/state overrides. Connection paths
and identity come from this resolver; no process environment is replaced, no
Node is launched, and no other deployment's environment is used as a fallback.
Every managed tool and frozen heartbeat revalidates the original complete pin.
An instance-only restart can recover; a changed pin cannot retarget the call.
Standard HTTP uses redirect refusal without consulting legacy PQTLS environment;
3xx responses do not confirm a result or heartbeat. Root-mode Network invitations
and Monitor broadcast operations lack a selected configuration and return
CONFIG_REQUIRED; their original explicit legacy flows remain available.

Local MCP session records add optional `connection_pin`, excluding instance ID.
The original scope hash stays unchanged. Root mode cannot activate or overwrite
an old unpinned cache, and cannot replace a differently pinned cache. A completed
Hook connect saves the complete pin with its session result before ACK. Original
operator-intent persistence, exact retry and output-before-ACK remain authoritative.

The original MCP outbox SQLite database adds one immutable metadata row in
`mcp_outbox_connection_pin` (format `cicada.mcp-outbox-connection.v1`). New root-mode
databases require an absent original DB and no residual WAL/SHM/journal. Exclusive
file creation precedes a FULL-synchronous transaction committing the complete
pin, then directory sync, before enabling WAL or storing operations. Existing
databases undergo a read-only main-DB fence check before opening for mutation;
missing pins return CONFIG_REQUIRED and changed pins return BINDING_CHANGED.
An empty DB left before pin commit is retained and cannot be silently adopted.
Original operation IDs, scopes, uncertain packages and file locations stay intact;
no new session record retroactively authorizes an old outbox-only namespace.

The current legacy consumer refuses new pinned caches/outboxes, preserving old
unpinned legacy records. Historical binaries do not understand these forward-only
fences: opening new pinned state with such a binary is an unsupported downgrade.
No automatic migration, grant, Owner/Node key replacement or public wire change
is part of this local consumer schema extension. New acceptance Threads use
explicitly new managed scopes; this is not evidence of migration of older scopes.

## Proposed Owner-managed Endpoint Groups v1

**SOURCE PHASE: INTEGRATED CANDIDATE, 2026-10-26.** Root approved the
contract at `e3544d9`. The Hub candidate adds schema 69, durable Owner and Node
transactions, bounded production HTTP/RPC handlers, exact receipts, original
registration renewal and per-Endpoint source Guards to the shared Go codecs.
The profile is `owner-endpoint-groups-v1`. The configured complete HubNodes
service now advertises Available and NativeSelfGroups; a bare DTO factory and
uninstalled service default to false. Availability describes implementation,
not caller authorization. Node/MCP and App implementations retain
separate commit and validation attribution; this Hub checkpoint claims no real
native Runtime or M1–M8 pass. The machine inventory remains the separate
`proposed_owner_endpoint_groups` object in `owner-endpoint-contract.json`.
It does not revise `native-endpoint-directory-v1`, the existing directory cards,
wire 1, the 55-operation Client catalog or Pair/legacy-profile Join semantics.

### Scope and objects

The Owner may create one named Group in the selected, already authorized
Network, or add/remove one **already explicitly registered** native Endpoint in
one Group. The first profile requires the same Owner, Hub, Network, approved
Node and actual local OS-user scope. An existing registered Thread retains its
SID, Endpoint, principal, workspace, original private key and native history.
No new identity is synthesized to make an admission succeed. Group creation
uses `group_scoped` and creates no Agent membership or communication grant.
The App can create G2 from its candidate list and subsequently review adding D;
the user never needs to transfer JSON or an opaque ID. Reserved Pair Groups are
ineligible. Parent changes, deletion, roles, bulk actions, foreign Owners,
cross-Network admission, Task, broadcast, Journal, Discussion and history sharing
are outside this profile.

The only Agent rights are the exact sorted set `directory.read,message.ask,
message.receive,message.reply,message.send`. Every actual Actor Guard must enforce
this source-specific five-right ceiling and current Owner-control, including
legacy paths and global mutations; a closed Hub Nodes route alone is insufficient.
Broader task/space or other grants on a shared Principal never enlarge this
managed Endpoint's authority. Unknown legacy sources reject, with no prefix
allowlist or fallback. Registration, a candidate card,
public capability and selecting a Group are not grants. A single native Thread
can retain plaintext memory from several Groups; `group_scoped` does not claim
Runtime memory isolation. Existing dedicated-context history Guards still deny
incompatible admission. The initial bound is 32 active Group relations per
Endpoint; reaching it refuses a new add without dropping history or receipts.

The new profile distinguishes three objects:

* **Registration/writer anchor:** the original registered native tuple and key
  custody, independent of any Group permission. Registration-only liveness has
  zero discovery, message, execution or membership rights.
* **Endpoint/Group relation:** `NONE -> PENDING_KEY -> ACTIVE -> REMOVED|EXPIRED`,
  with a monotonic aggregate `relation_revision`, a separate monotonic
  Owner-decision revision, and independent source contributions. Both
  DEFAULT_POLICY and OWNER_EXPLICIT may contribute to the same relation.
  Each retains its own authority ID/epoch, contribution revision, state,
  deadline and key readiness; they are not merged into a synthetic grant.
* **Manual delegation:** `PENDING_KEY -> ACTIVE -> REVOKED|EXPIRED`, with an
  immutable policy ID/epoch, exact scope and Owner proof. A new explicit add
  after removal creates a higher policy epoch; it never revives a terminal one.

Every stable native-identity/Group pair also has a durable Owner-control head:
`mode,revision,deny_reason,policy_id,policy_epoch`. Mode is DEFAULT or OWNER;
deny reason is NONE, REMOVED or EXPIRED, and revision equals decision_revision.
Policy reference denotes the last activated manual policy, possibly terminal.
An untouched relation starts DEFAULT/revision 0/NONE. A successful manual
key_complete atomically switches it to OWNER and the new policy; REMOVE switches
it to OWNER/REMOVED. OWNER mode is permanent: no expiry, default-policy refresh,
new Endpoint/token/epoch, literal Join or new operation can switch it back.
There is no return-to-default action in v1.

OwnerControlDigest is SHA-256 of
`cicada/owner/endpoint-groups/owner-control/v1\0` and typed JSON
`native_identity_digest,group_id,head`, where head has the exact five fields above.
The private native key is not disclosed; the digest commits that stable key and
Group together. It is carried in review CAS, the policy's expected head,
projected Node grant and fresh sender/receiver current evidence.

In DEFAULT mode with no deny, only independently current DEFAULT_POLICY authority
is effective. A pending manual contribution grants nothing and does not lower an
already ACTIVE, never-denied default relation. Once manual completion commits
OWNER mode, only the exact activated manual policy can supply rights; the stored
default contribution becomes ineffective even if its own policy is still valid.
Manual expiry keeps OWNER control and produces EXPIRED/deny, never fallback to a
permanent default grant. A prior REMOVED/EXPIRED deny remains in force throughout
new manual PENDING_KEY. Only a newly Owner-authorized, exactly projected Complete
at the expected head can clear it. Apply alone never clears deny or takes over.

Effective state is ACTIVE only with the source permitted by that head and its
current key/five rights. It is REMOVED or EXPIRED while the corresponding deny
applies, even if a replacement manual contribution is pending; otherwise an
unauthorized pending edge is PENDING_KEY, revoked edges are REMOVED and absence
is NONE. Effective expiry comes from that one controlling source, not the maximum
of source deadlines. Expiry is checked against trusted time at every Guard,
independent of lazy materialization; recording an Owner-approved expiry advances
the head/listing revision and never grants permission. Cards/receipts retain both
contribution provenance and the head/effective state. Each contribution reports
effective and unavailable_reason, so a stored ACTIVE default cannot masquerade
as effective after Owner takeover.

Every peer proof chooses the one controlling source explicitly. Neither an old
operation nor a new one may bypass OWNER mode with default proof. Different
Endpoints in the same Group may still use different independently verified
default/manual sources. A contribution update advances aggregate relation CAS
without invalidating an unchanged controlling contribution's key evidence.
Key-grant relation digests bind contribution_revision, decision_revision and
Owner-control digest rather than an unrelated source's aggregate update.

An Owner removal persists a deny for the exact stable native identity/Group.
The private native-identity digest is SHA-256 of UTF-8
`cicada/owner/endpoint-groups/native-identity/v1\0` and canonical typed JSON
`hub_id,owner_id,node_id,local_user_scope,harness,native_session_id,workspace`.
It excludes Endpoint/principal IDs, tokens, binding/policy epochs and keys;
the deny key is `(native_identity_digest,group_id)`. Only server/Node derive it
from actual original coordinates. It is not a caller input or an Owner/public
card field and exposes no SID. The separate registration_digest below includes
Endpoint identity and cannot serve as the anti-replacement deny key.
The deny overrides default admission across
warm/cold renewal, new Attempts, token changes, Node/MCP restart and exact old
receipt recovery. Changing Endpoint IDs or policy epochs cannot erase that
identity's deny. Only a new Owner-signed add for that exact relation, using the
current decision revision, followed by exact successful key_complete can clear
it. The stable key also stores permanent OWNER control after a manual grant
expires, regardless of an old default source. Ordinary Thread registration/Join is
unchanged and must not silently clear it. A denied default-Group admission
returns OWNER_READD_REQUIRED; it must not report a successful Group Join merely
because the native registration still exists. Deny history is durable, including
through backup/restore; no cache eviction can turn an old removal into absence.

### Capability, operations and closed DTOs

The following identifiers are Root-reviewed; they are not an enabled API.
Only exact listed paths/methods may later be composed into Hub Nodes. Shared Go
constructors/codecs do not install HTTP handlers or authorize callers.

| Carrier | Operation | Path / purpose |
| --- | --- | --- |
| GET | capability, no actor authority | `/v2/owner/endpoint-groups/capabilities` |
| POST | `owner.endpoint_groups.read` | `/v2/owner/endpoint-groups/read`; `owner-endpoint-groups-read:v1` |
| POST | `owner.endpoint_groups.prepare` | `/v2/owner/endpoint-groups/prepare`; `owner-endpoint-groups-prepare:v1` |
| POST | `owner.endpoint_groups.apply` | `/v2/owner/endpoint-groups/apply`; `owner-endpoint-groups-apply:v1` |
| POST | `owner.endpoint_groups.status` | `/v2/owner/endpoint-groups/status`; `owner-endpoint-groups-status:v1` |
| POST | `owner.endpoint_groups.reconcile` | `/v2/owner/endpoint-groups/reconcile`; `owner-endpoint-groups-reconcile:v1` |

All five requests have the closed envelope
`format,context,session_token,owner_proof,body`; `format` is
`cicada.owner-endpoint-groups.v1`. `context` retains the existing typed App
account/device/Hub/origin/epoch/request coordinates. A fresh independent Owner
request proof covers its exact purpose, context and canonical body digest;
account login/device authentication alone grants nothing. Request claims are
`version,purpose,scope,request_id,nonce,issued_at,expires_at,body_digest`, using
the existing `OwnerAppNodeScope`. Canonical request signatures use UTF-8
`cicada/owner/endpoint-groups/request/v1\0` followed by typed claims JSON.
The maximum request/review lifetime is 300 seconds with at most 30 seconds future
skew, bounded further by the original account/device/Owner authority. A new
login or Node report never extends an original review.

BodyDigest and PacketDigest are lowercase SHA-256 of, respectively,
`cicada/owner/endpoint-groups/body/v1\0` plus canonical typed body JSON and
`cicada/owner/endpoint-groups/packet/v1\0` plus the exact original encrypted
Owner packet bytes. Canonical typed JSON uses declared field order, ordinary
Go JSON escaping and no whitespace. PolicyDigest is SHA-256 of the policy
signature input described below, without the signature. Node RPC originals
retain SHA-256 of the exact Node packet (`nodewire.RecoveryDigest`) and their
existing replay ledger. This does not change old LocalDomain recovery's retained
historical prefixed digest.

The machine inventory lists every closed field set in canonical DTO order;
unknown fields, duplicate JSON keys, invalid UTF-8, noncanonical UTC times,
fractional/overflowing versions and unknown enum values reject. Target IDs are
selections from authorized cards, not asserted caller identity. Neither Owner
requests nor cards accept a caller-supplied SID, token, credential path, key
substitution or free-form grants.

* `read.body = {view,node_id,network_id,endpoint_id,cursor,limit}`. `view` is
  THREADS, CANDIDATE_GROUPS or RELATIONS. THREADS permits an empty Endpoint
  selector; the other views require the exact registered Endpoint. Omitted cursor is
  empty and omitted limit is 64; range is 1..64. All results are private Owner
  snapshots, paginated by opaque scope-bound cursor, at most 128 KiB canonical
  plaintext per page. Presence does not establish live Runtime consumption.
* `prepare.body` is a strict action union. CREATE_GROUP has
  `action,node_id,network_id,name`; ADD_ENDPOINT has
  `action,node_id,network_id,group_id,endpoint_id,duration`; REMOVE_ENDPOINT has
  `action,node_id,network_id,group_id,endpoint_id`. Names are nonempty, trimmed,
  valid UTF-8, at most 128 bytes and contain no control characters. The selected
  Node/Network must already belong to the authenticated Owner. No agent is
  auto-enrolled by CREATE_GROUP.
* `apply.body = {review_id,review_digest,prepare_packet_digest,policy_proof}`.
  Policy proof is mandatory only for ADD_ENDPOINT and absent for the other
  actions. The fresh apply request proof authorizes the exact reviewed effect.
* `status.body = {operation_id,original_packet_digest}` queries the original
  device's apply operation and a separate current-state snapshot, without redispatch.
  Operation ID is the original apply `context.request_id`, known and persisted
  by the App before sending, even when every response is lost. Its digest is
  PacketDigest of that exact original encrypted **apply request**, never the
  prepare, status, response or a newly encrypted equivalent. No new operation-ID
  allocation or returned-ID dependency is introduced.
* `reconcile.body = {original_packet}` embeds the exact encrypted original
  read/prepare/apply/status request, never another reconcile. The same currently
  authenticated original device and retained cryptographic scope are required.
  A different enrolled App can read authorized current Group state, but cannot
  borrow another device's encrypted receipts or private pending state.

Capability format is `cicada.owner-endpoint-groups-capabilities.v1`. Its closed
fields are `format,contract_revision,available,hub_id,hub_fingerprint,
max_page_rows,max_page_canonical_bytes,max_active_groups_per_endpoint,
duration_values,native_self_groups`. Hub fingerprint must independently match the selected Hub.
Public availability remains false until the complete bounded implementation
and required same-source gates pass; a true flag never supplies Owner authority.
native_self_groups is also false in this contract-only checkpoint.

The new private Thread card has
`endpoint_id,principal_id,node_id,network_id,name,workspace,harness,registration_digest,
registration_revision,presence,relations,relation_states,relations_revision,
relations_complete,relations_next_cursor`. A relation card has
`group_id,group_name,network_id,state,relation_revision,decision_revision,manual_deny,owner_control,
contributions,selected_source,expires_at,key_state,allowed_actions,unavailable_reason`.
A contribution has `source,authority_id,authority_epoch,contribution_revision,
state,expires_at,key_state,effective,unavailable_reason`; selected_source is the exact source/authority/epoch
reference (`source,authority_id,authority_epoch,contribution_revision`) in a
current observation, not authority inferred from the list. It is null when no
current proof source was selected; a private read does not create a peer proof.
A candidate Group card has `group_id,name,network_id,group_version,
context_policy,allowed_actions,unavailable_reason`. Key states are
`NOT_READY,PENDING,CURRENT,STALE,REVOKED,EXPIRED`. Allowed actions are bounded
server-derived CREATE_GROUP/ADD_ENDPOINT/REMOVE_ENDPOINT choices; disabled or
absent choices cannot be inferred from display names. The old Owner directory
card remains exactly `endpoint_id,name,workspace,harness,presence`.

Every successful read returns independent scope_actions with
`node_id,network_id,allowed_actions,unavailable_reason`. CREATE_GROUP is decided
by the current authenticated Owner's exact Node/Network management authority,
even when `groups=[]`; it is never inferred from public capability or a fake
Group card. Prepare/apply still repeat the current Owner proof and Guards.

Thread.relations is the first **at most eight** current relation projections
for that exact Endpoint/current Network, ordered by Group ID. It includes every
stored relation state (PENDING_KEY, ACTIVE, REMOVED, EXPIRED), not unbounded
operation history; NONE means no stored relation. relation_states explicitly
records this filter. The 32-active limit is not a terminal-history limit.
relations_complete is true only when the whole matching relation set was
observed; otherwise relations_next_cursor is nonempty. Absence on an incomplete
page proves nothing. App fetches RELATIONS pages with that exact cursor/Endpoint/
Network; results use `relations` plus relation_page fields
`endpoint_id,network_id,states,relations_revision,complete,next_cursor`.
Each page is at most 64 relations and 128 KiB; THREADS pages also stop at the
same aggregate byte bound rather than promising 64 fully populated cards.

relations_revision is an Endpoint/Network listing revision advanced by relation
authority/source/state changes, never heartbeat. Cursors bind the authenticated
Owner, Node, Endpoint, Network, state filter and this revision. A changed set
returns CURSOR_STALE; App restarts a complete read while retaining its known
state and pending operations. Only a complete same-revision traversal may show
that a relation is absent. Each relation's contributions has at most two current
source slots, one DEFAULT_POLICY and one OWNER_EXPLICIT, including a slot's
latest terminal state. Older policy epochs and operation history remain durable
and are recovered by their exact operations, not embedded in these cards.

The new result format is `cicada.owner-endpoint-groups-result.v1`, with ordered
fields `format,contract_revision,request_id,request_packet_digest,hub_id,owner_id,
device_id,node_id,state,error_code,captured_at,freshness,threads,groups,relations,
scope_actions,relation_page,next_cursor,review,operation,current_relation,
current_group,receipt_packet`. Only action-applicable payloads are present;
snapshots say `freshness=SNAPSHOT_ONLY`. A reconcile response contains the exact
original encrypted receipt, without rewriting it to current authority.
Target/projection, policy/proof, current-relation and Node request field sets
are closed and ordered by the inventory's corresponding `*_fields` and
`node_request_bodies` entries. The ADD projection's `policy_core` is the entire
typed policy except `review_id,review_digest`; its initial grants are empty
and its projected rights are the exact five-item set. ADD projection explicitly
separates contribution_state=PENDING_KEY from effective_relation_state, which
can remain ACTIVE through an existing default contribution but remains blocked
while an existing Owner deny applies. expected_owner_control is the unchanged
apply-time head; completion_owner_control is the precise future OWNER/NONE head
with revision +1 and the new policy reference, committed only at Complete.
REMOVE projects
`manual_deny=true,withdraw_scope=EXACT_ENDPOINT_GROUP`; CREATE projects
`owner_management_only=true` and no Agent grant.

The original registration commitment is SHA-256 of UTF-8
`cicada/owner/endpoint-groups/registration/v1\0` followed by canonical typed JSON
`hub_id,owner_id,node_id,harness,native_session_id,workspace,endpoint_id,
principal_id`. The Node recomputes it from its exact original record and Hub
registration. SID is not exposed in the Owner card. Registration revision tracks
authority coordinates, not heartbeat timestamps or display-name edits.

### Review, CAS and persistent manual delegation

Preview fields are `review_id,request_id,request_packet_digest,action,target,
expected,projection,policy,key_manifest,observed_at,expires_at,review_digest`.
Unused action fields are absent. CREATE_GROUP target contains the selected
Owner/Node/Network, server-reserved Group ID, name and `group_scoped`; add/remove
target additionally fixes the exact Endpoint/principal/registration and Group.
The projection records the complete resulting action, rights, source, expiry
and unsigned policy core, without granting access. It never reserves a Pair.

ReviewDigest is SHA-256 of UTF-8 `cicada/owner/endpoint-groups/review/v1\0` and
canonical typed JSON of `review_id,request_id,request_packet_digest,action,
target,expected,projection,key_manifest,observed_at,expires_at`. `policy` and
`review_digest` are excluded to avoid self-reference: the Owner must compare
every unsigned policy core field to the projection, then add this review ID and
digest before signing. Key-manifest claims and candidate self-attestation are
independently verified before approval; a Hub label is insufficient.

Expected coordinates are `owner_key_version,node_owner_binding_id,
node_owner_binding_version,node_key_epoch,network_version,group_version,
registration_digest,registration_revision,binding_id,binding_epoch,
candidate_version,candidate_proof_digest,candidate_fingerprint,
membership_revision,endpoint_join_revision,relation_revision,decision_revision,
owner_control_digest,policy_epoch`.
CREATE_GROUP uses only its applicable Owner/Node/Network coordinates and absence
of the reserved ID. Add/remove use the complete applicable current snapshot;
an absent prior relation has explicit zero revisions. Heartbeat row version,
lease expiry and observation timestamps are not authority CAS coordinates.
Taking the SQLite writer precedes trusted-time sampling and current checks.
The same transaction commits precise effects, nonce/sequence consumption and
the exact encrypted response; concurrent changes return CAS_CONFLICT rather
than editing or silently restoring a snapshot.

The target must be the registered Agent principal, never the human Owner.
Reuse an existing principal/Group Membership only when it already authorizes
the five rights; the Endpoint's exact manual relation still limits its effective
rights to that set. Do not bump a shared Membership or widen/revoke its grants
to operate on D. If creating or changing that row would alter another Endpoint's
authority/key snapshot, return SHARED_MEMBERSHIP_CONFLICT without effects; general
principal-role repair is outside v1. If reuse cannot preserve other Endpoints
while enforcing this Endpoint's five-right ceiling at every actual Guard,
return SHARED_MEMBERSHIP_CONFLICT or UNSUPPORTED_PROFILE without effects.
An absent, unshared Membership may be created
zero-right and activated atomically with D's exact relation/grant. All peer
Guards continue checking both principal membership and the active Endpoint edge.

ADD_ENDPOINT uses a new exact persistent policy with purpose
`endpoint-group-policy:v1`, signed through the existing ML-DSA primitive over
`cicada/owner/endpoint-groups/policy/v1\0` and canonical typed policy JSON.
Its complete field order is defined by `policy_fields` in the inventory. It
includes the actual Owner identity/version, complete approved Node binding and
Control key, actual local-user scope, exact Hub/origin/Network/Group/Endpoint/
principal, original registration commitment, binding ID/epoch, original Endpoint
public key/fingerprint/candidate evidence, expected_owner_control_digest and
expected_decision_revision from this exact Owner review, the five rights, review
binding and server nonce. It delegates no registration of other Threads and no other Group.

Duration is explicitly `until_revoked` (App default), `1d`, `7d` or `30d`.
For until_revoked the policy's `expires_at` is empty; otherwise it is exactly
the original review observation time plus 86400, 604800 or 2592000 seconds.
Apply, traffic, login, heartbeat, retry and restart never extend it. The short
request/review expiry does not expire this business policy. Only this typed
persistent delegated verifier accepts empty expiry: existing finite
`OwnerGroupEndpointKeyGrant`, Link and Pair verifiers remain unchanged.

Apply durably commits the new OWNER_EXPLICIT contribution as PENDING_KEY with
zero rights of its own. It never replaces an ACTIVE DEFAULT_POLICY contribution,
zeros that effective edge or resets its Membership/grants/key snapshot. Effective
state may remain ACTIVE through the default source while the manual source is
pending if the head is DEFAULT with no deny. Existing REMOVED/EXPIRED Owner
deny stays effective during pending, with the head/revision unchanged. Apply
only adds the pending contribution and advances aggregate relation/listing CAS;
it never clears deny. A second fresh add while the manual source
is ACTIVE or PENDING_KEY returns MANUAL_SOURCE_ALREADY_ACTIVE or RELATION_PENDING
without allocating another slot; exact retries recover only their original.
A missing/changed original private key, stale candidate or failed Node proof
cannot be replaced. App closure is allowed after durable submission, but UI
must distinguish the pending manual contribution from any existing active source.

Node operations use the existing signed/encrypted `/v2/node/control/rpc` carrier:
`node.endpoint_groups.describe,key_prepare,key_complete,renew,reconcile`.
Describe is restricted to the authenticated Node's original registered
Endpoint/user; it is not an Owner inventory. Key prepare freezes the old CAS
snapshot and the complete projected ACTIVE source relation and Group manifest,
including post-completion contribution, Membership and Endpoint-join revisions.
Its closed result is `challenge_id,policy_id,policy_epoch,expected,
projected_owner_control,projected_relation,projected_key_manifest,observed_at,
expires_at,challenge_digest`. The old Owner-control head must still match the
Owner policy's expected digest/revision. The projected head is exactly the
reviewed completion_owner_control: OWNER/NONE, revision +1, this policy ID/epoch.
Node signs that same projected head and ACTIVE relation/manifest together.
ChallengeDigest is SHA-256 of
`cicada/owner/endpoint-groups/key-challenge/v1\0` plus those canonical fields
except challenge_digest. Existing active default/shared rows are unchanged in
the projection; only an absent unshared zero-right Membership may advance.
The Node signs projected ACTIVE state, never pre-state with ignored revisions.
Stale old CAS or changed projected bytes/digests reject completion. A fresh
prepare under the same still-valid exact policy may observe unrelated source
updates only while the original Owner-control head is unchanged. It cannot
rebase consent over a later removal/expiry/Owner decision, or change key/binding;
those require a new Owner review.
Before signing, the Node compares the independently pinned original Owner,
policy/Node chain, registration commitment, binding and candidate with its
actual retained record/key. Key complete signs purpose
`endpoint-group-key-grant:v1` using `cicada/node/endpoint-groups/key-grant/v1\0`.
The signed claims bind policy digest, projected relation/manifest digest,
candidate binding digest, projected Owner-control digest, challenge ID/digest
and validity. Relation
digest uses `cicada/owner/endpoint-groups/relation/v1\0` and the complete typed
current relation, including registration, decision, source, membership/join
revisions and key/binding coordinates. Completion rechecks all current authority
and commits only that same projected head/relation/manifest. In one transaction
it switches control to OWNER, clears the old deny, installs the exact policy
reference and manual ACTIVE evidence/rights, and makes default ineffective
without deleting its provenance. Recalculating
different revisions and ignoring a mismatch is forbidden.
Pure describe never signs, creates membership or advances an authorization epoch.

The enrolled native context profile for this initial extension is
**OWNER_ENDPOINT_GROUPS_V1**, limited to already registered Codex/LocalDomain
origins. Other registration origins are explicitly unsupported for this new
management profile; their established old capabilities remain unchanged.
The private Node issuer chooses this profile from its protected registration
anchor, never model input or a current default-policy selector. It verifies the
original exact transcript path/SID/canonical cwd, actual OS user, current approved
Node/Owner key chain, original Endpoint key/candidate and binding ID/epoch.
Once enrolled, these identity checks do not require the default policy to remain
active. No record scan, startup SID or legacy fallback establishes identity.

The consumed context retains the existing harness/SID/workspace/actual event IDs
and adds `verification_profile=OWNER_ENDPOINT_GROUPS_V1,endpoint_groups_version=1,
registration_digest,registration_revision,binding_id,binding_epoch,node_key_epoch`.
LocalDomain and Pair selectors are absent in this variant. Unknown, partial or
mixed profiles refuse. Issue/consume still bind the actual original selected
Node pin/origin, one-use ticket, connection nonce, exact tool/business-argument
digest and event IDs, with the existing 30-second ticket limit. This is identity
proof only; subsequent scope/business calls separately require their exact
active Group/source and deny Guards. Restoring this profile/cache or renewing
its frozen heartbeat must not require a live default policy, silently downgrade
to LEGACY_STRICT, reuse a consumed ticket or skip the Hook. A revoked Owner/Node
or changed key/epoch cannot be repaired with another profile. M5 requires fresh
post-revoke Hook issue/consume and new MCP processes, not just saved leases.

If this profile's original Describe has an uncertain transport timeout, the
same issue may make at most one bounded recovery attempt for that exact read's
operation ID, sequence and ciphertext. Recovery must fit the original private
connection deadline, then obtain a fresh Describe and repeat the full original
registration, native-record, Owner/key and binding checks before issuing a
ticket. A historical read receipt alone is not current authority. Each network
attempt retains its five-second bound; the existing thirty-second connection,
thirty-five-second client/Hook bounds and thirty-second minted ticket lifetime
are unchanged. Lock waiting does not restart the original connection budget.
Authorization refusals, invalid proof, identity changes, local capacity errors
and pending writes do not authorize automatic retry or business redispatch.

The Node may retire a settled KeyPrepare Challenge response only when its
original registration's retained, authenticated successful Complete proves the
same scope, Challenge and exact projected policy, head, relation and manifest.
Existing cryptographic checks use the original observation times solely to
establish this historical cache dependency, never current authority. Retirement
keeps the read's original request, body, ID/digest and settled tombstone, every
Complete receipt, original identity/anchor, current grants and Owner heads/deny.
Any pending Node RPC or retained execution state prevents retirement. An exact
replay of a retired read returns the existing local receipt-expired result
without network dispatch; changing its body remains a conflict. Retirement
persists atomically and does not change the 8MiB state bound or 2MiB response
reservation.

A settled ACTIVE KeyPrepare response may be retired only within that same
original registration intent when its authenticated grant and Owner head
exactly match a retained successful Complete for the same Endpoint and Group.
The existing-only, read-only Node high-water lookup must confirm the original
registration, independent active Owner pin and immutable identity scope, and
recompute the stored head digest. Retirement then requires either a retained,
authenticated successful Complete for that same original scope whose strictly
higher policy epoch and Owner-head revision exactly match the stored OWNER/NONE
head, or a stored OWNER/REMOVED or OWNER/EXPIRED head with a strictly higher
revision and a policy epoch at least as high as the old grant. At the same epoch,
the terminal head must retain the same policy ID. A pending policy or cached
authority projection alone does not prove this permanent supersession.

Terminal observations may retain the previous identity snapshot; its immutable
scope must still match, while its old decision fields are not compared with the
new terminal head. This lookup never advances a head or grants current business
authority. Only the superseded read response bytes are removed. Any ACTIVE read
whose authority remains current, every request/body/ID and settled tombstone,
every write and Complete receipt, original keys/registration, current grants and
Owner heads/deny remain intact. The same pending-state fences, atomic persistence,
receipt-expired/conflict replay rules, capacity bounds and deadlines apply.

The `endpoint_group_grant` peer carrier contains the complete existing Group manifest, original
candidate attestation, exact Owner policy proof, Node delegated proof and fresh
Hub-authenticated current relation/operation/attempt. Manifest optional expiry
equals policy expiry. This is a distinct delegated variant with exactly one
verified authority source **per Endpoint**; it is not a forged legacy Owner
grant. The new `endpoint_group_current` format is
`cicada.endpoint-group-current.v1`, with exact sender and receiver relation
snapshots and operation/attempt/deadline. Each sender/receiver snapshot has
`owner_control,relation`; the selected relation's owner_control_digest must
match that head and stable native/Group key. An active default-policy Endpoint and
an independently manual-authorized Endpoint may communicate in their exact
shared Group only through this checked per-Endpoint source union. Both original
chains must be current; a default grant is never converted into manual authority.
Multiple evidence variants for one Endpoint, unknown variants and fallback from
a stale verifier reject. Existing Pair evidence is not admitted by this profile.
Both source and target Nodes independently check
Owner trust and the exact same Group/current key evidence before sealing or
opening. No Hub-supplied public key replaces the independent Owner pin.
REPLY reverses both Endpoint sources in the current evidence while retaining
their original registration, keys, bindings and Owner heads. Its final delivery
carrier must include that reversed current for the exact native-delivery
attempt; acceptance or claim does not substitute for the Node's verification.

### Removal, independent renewal and original-packet recovery

A successful recovered Node KeyComplete includes bounded local installation of
that exact original grant before its pending outbox is released. The Node binds
the original origin/registration, current retained Owner pin, Node key/epoch and
exact Prepare generation/Challenge, verifies the complete projection through the
existing crypto checks, and writes the monotonic Owner head within the caller's
remaining budget (at most five seconds). No new RPC, identity or authorization
is created. Historical `ObservedAt` authenticates the old result; actual current
time is read again immediately before installation. Fresh Current and Hub Guard
remain independently required for business use; their lifetimes do not change.

The authenticated response is durable before local installation. A crash before
installation or control-state cleanup retries the same original and response;
installation is idempotent. Unknown/mixed origins, missing exact evidence,
I/O failures and canceled budgets retain the pending original for retry. Only
a fully authenticated historical success independently proved obsolete by an
exact revoked Owner pin, an expired policy, or a strictly newer stored Owner head
may settle without installing its grant. A same-epoch newer head must name the
same policy; a newer epoch may name its replacement. This preserves the newer
deny/head and original settled receipt, clears the obsolete outbox and returns
an explicit local terminal result (`OWNER_PIN_REVOKED`, `POLICY_EXPIRED` or
`SUPERSEDED_HEAD`). These are local recovery classifications, not new wire errors
or current authorization. Generic policy/conflict errors cannot imply terminal
obsolescence or justify discarding an unknown pending action.

REMOVE_ENDPOINT withdraws all contributions to only the exact Endpoint/Group edge,
advances the decision/relation revision and installs the permanent manual deny.
It invalidates that edge's prior key evidence, selections and new work at the
existing current Guards. Do not revoke the shared Owner/principal, whole
Network, Node, other Endpoints or other Groups. If a principal has multiple
Endpoints, its other relations/grants remain intact; membership changes must not
invalidate their key snapshots. Removal works while the target Node is offline.
The receipt lists every withdrawn contribution and the resulting deny/decision
revision and resulting OWNER/REMOVED head. Default-policy revoke instead
withdraws only its own contribution,
leaving an active manual contribution even in that same Group intact.
Owner/Node root revocation remains broader and fences every dependent Group.

Default policy expiry/revocation withdraws only that policy's contribution.
It must not revoke Network enrollment/access, registration/writer liveness or
another Group supported by an independent manual policy. Explicit manual
authorization in the default Group is also separate from its default source.
Policy provenance and deny precedence must be stored and checked transactionally;
the current unconditional LocalDomain termination and primary-Group lease paths
cannot merely be forwarded unchanged. This exception belongs only to the new
reviewed profile; it is not a global relaxation of legacy enrollment/key guards.

Renewal sources are REGISTRATION_ONLY, DEFAULT_POLICY and OWNER_EXPLICIT.
Registration-only renewal verifies original explicit registration, current
Owner-approved Node/writer, actual original record and exact retained key;
it grants zero Group or Network business rights. Independent Group renewal
additionally checks that Group's actual source, current Owner policy, relation,
deny generation, membership, key and policy expiry. Node/control expiry or
revocation still refuses. A default-policy grant can never lend G1 authority to
G2. Warm heartbeat uses the existing bounded heartbeat mechanism without a
per-tick permanent mutation receipt; cold renewal uses its exact Node original
and replay ledger, preserving original credentials/access IDs and binding ID/epoch
in every normal warm/cold recovery. A real binding epoch, Endpoint key or Node
authority change requires a new exact Owner authorization; it cannot be absorbed
by renewal or an unreviewed current-authority transition. No unknown renewal
rotates a substitute token. An App session, read cache
or process presence is not a renewal source.

The retained Network identity can serve self identity, native self-binding and
registration renewal only. Once the Endpoint has an explicit registration,
wider Principal Network grants cannot authorize directory discovery, direct
send/receive, task/broadcast operations or global Network Leave for that
Endpoint. Apply this ceiling in service authorization and the same transaction
as business reads/writes, including each participant of a bilateral operation.
An expired source or registration lease does not restore legacy Network rights.
Existing independently enrolled Endpoints without this registration retain
their separately authorized Network behavior.

Removing the final Group leaves an explicitly registered, zero-business-rights
Thread and its original key/history; it does not call global Endpoint Leave,
delete a Thread, stop the Node or erase registration. Native injection still
requires an exact active relation and fresh final authorization. Selecting a
scope (`cicada_use_group`) only chooses an already active authorized Group and
creates no admission or key grant. A removed saved selection on restart must
not delete still-valid registration credentials for another Group. Restore the
exact sender from original private enrollment/receipts and return a typed
selection-required state when needed; never auto-Join, choose a replacement
Group or borrow another Thread's context. Verification of the original native
record is based on its enrolled context/profile and current exact manual proof,
not permission borrowed from a now-revoked default Group. The existing fresh
one-use Hook context and dedicated-context history fences remain mandatory.

For the new profile, explicit Join/Leave only enable/disable this Thread's
local Endpoint access. Leave persists local offline state, clears the saved
selection and stops that anchor's renewal; it does not withdraw Owner Group
configuration, globally leave the Endpoint, stop the Node or kill Codex. Join
checks the same original registration and current Owner/Node before restoring
local access, and never auto-selects a Group. With no usable Groups it reports
registration ready and asks the Owner to add one. Legacy global/Group Leave
cannot borrow these five rights.

A managed empty-Group POST to the existing `/v2/fabric/heartbeat` renews only
the still-live original registration token/anchor under current Owner and Node
checks. It returns no Group or membership authority, creates no permanent Node
mutation receipt, and works after G1 denial or removal of the last Group. It
cannot resume an expired lease: cold renewal still requires the original
currently approved signed Node request. Both bounded HubNodes and full Fabric
routers enforce this same narrow path; general AuthenticateForGroup is unchanged.

Linux terminal `join --thread ID --name NAME` / `leave --thread ID` are thin
local operator entries. The ID only selects a real owned Codex record; existing
private Node discovery, original anchor and one-use invocation proof remain
mandatory. No native Hook event, turn/tool ID or environment SID is synthesized.
Each MCP call still authenticates its actual current Thread independently.

The proposed read-only MCP tool **cicada_groups** supplies the missing self-scope
list. Business parameters are the closed `{cursor?,limit?}` (default 64, integer
1..64), with no model identity, Endpoint, Node, Network or Group selector. It
requires a fresh one-use OWNER_ENDPOINT_GROUPS_V1 context and original enrolled
sender, but **no selected Group**. It derives exact Endpoint/Network from that
private registration and uses authenticated Node `node.endpoint_groups.describe`
plus the existing Endpoint-group relation query. It exposes only this caller's
currently usable ACTIVE, key-ready, unexpired relations, never Owner inventory,
pending/removed peers, global directories or another Thread's memberships.

Result fields are `groups,current_group_id,selection_required,complete,
next_cursor,freshness`; cards are `group_id,name,network_id,current,
relation_revision,source,expires_at,freshness`, with SNAPSHOT_ONLY freshness.
Pages are bounded to 64 rows/128 KiB and exact self-scope cursors; stale cursors
refuse and restart rather than proving absence. The internal IDs let the AI
uniquely match the returned Group name and call existing cicada_use_group;
the user need not copy IDs from the App. Same-name ambiguity requires explicit
user choice, never first-match selection. If the prior selection was removed or
no Group is selected, current_group_id is empty and selection_required is true;
even a single surviving Group is not auto-selected. Empty results are valid for
a registered zero-right caller and never trigger Join.

An explicit cicada_use_group after this list still performs its fresh context
and exact current Group Guard, and must be callable from registered-but-unselected
state without requiring re-Join. Neither tool creates relation/key authority.
Old/unknown profiles return UNSUPPORTED_PROFILE for this new list, preserving
their old behavior. The integrated Node candidate advertises it only for the
verified new profile; the Hub capability describes this availability and supplies
no per-caller authorization.

The encrypted operation ledger states are PREPARED, COMPLETED,
REJECTED_FENCED and READ_EXPIRED. A completed apply may have a PENDING_KEY
manual contribution; its receipt must not claim that contribution is active. Exact request ID and
packet digest recover only the original outcome, including after restart,
timeout, App login expiry or later revocation. Same ID/different packet is
ORIGINAL_PACKET_CONFLICT. Reconcile authenticates the original device/packet
and returns its durable receipt or a permanent no-effect fence; it cannot extend
a review, clear deny or redispatch a replacement operation. Unsettled results
remain OUTCOME_UNCERTAIN, never success inferred from a similarly named Group.
Current state is a separately labelled snapshot, not rewritten historical proof.

The immutable operation DTO is `operation_id,original_packet_digest,action,state,
error_code,review_id,target,committed_at,effect`. For an apply result and all its
status/reconcile results, operation_id is the original apply request ID and
original_packet_digest hashes that apply ciphertext. Its terminal state is
COMPLETED or REJECTED_FENCED; a rejected operation has no effect. CREATE effect
is `{group_id,created:true}`. ADD effect records exact Group/Endpoint, committed
relation/decision revisions, policy ID/epoch, contribution revision,
`contribution_state=PENDING_KEY`, the unchanged apply-time owner_control and
actual effective relation state (including an existing deny).
REMOVE effect records exact Group/Endpoint, new relation/decision revisions,
all withdrawn source references, `manual_deny:true,relation_state:REMOVED`,
and the resulting OWNER/REMOVED owner_control head.
Closed effect field sets are in the machine inventory. Historical metadata is
never rewritten when Node later activates or a policy is revoked.

The original apply response has no recursive embedded copy of itself. Fresh
status/reconcile can return that exact encrypted response in top-level
receipt_packet, separate from freshly guarded current_relation/current_group
snapshots. A successful status read is not an applied mutation. An absent operation row,
timeout or incomplete reconciliation leaves OUTCOME_UNCERTAIN; App retains its
original ciphertext/pending intent and never clears it, allocates another ID,
or infers success from a directory/card. Only authenticated terminal original
receipt or permanent no-effect fence settles that pending mutation.

For this profile, reconcile never executes an unseen original request, including
while its old proof/review remains fresh. When both permanent request floor and
operation receipt are absent, the writer atomically records an immutable no-effect
fence. An unseen original APPLY gets an exact original-route sealed
REJECTED_FENCED receipt with error ORIGINAL_NOT_ADMITTED, empty NodeID, nil
Operation and no cards/current/review/recursive receipt. This is the only
targetless original APPLY exception; missing/expired review cannot manufacture
its old target. A fresh wrapper embeds that exact original receipt. The App
opens it using the retained original ciphertext and calls
VerifyOwnerEndpointGroupsOriginalFence before settling pending. The wrapper's
NodeID may also be empty when GC removed the target. That exception is accepted
only after independently opening and verifying the exact nested original fence;
all other completed operations bind their retained target Node. The wrapper's
status/error, a missing row or a timeout cannot settle it. Unseen original
read/prepare/status gets READ_EXPIRED without performing a new read.
If a floor exists but its receipt is missing, return OUTCOME_UNCERTAIN and retain
pending. Direct retransmission of the same fresh unseen APPLY remains normal
first admission; the SQLite writer determines whether that admission or the
reconcile fence wins. Once fenced, later original retries return that fence and
never execute. A new review/new ID is a separately explicit Owner intent.

SQLite writer commit of fresh final authorization for the exact native attempt
remains the in-flight boundary. A remove committed before it denies queued,
claimed and new work; an already authorized attempt can remain in flight only
within its original at-most-30-second validity. This is not an atomic Hub/OS
operation or rollback of native side effects. Old requests, replies, selections
and outboxes retain their original Group/Network/Link; no surviving G2 authority
can redispatch a G1 operation.

### Bounds, compatibility and required validation

Bounds reuse the delegated-domain envelopes without enlarging legacy routes:
Owner proof 32 KiB, body 192 KiB, original 256 KiB, packet 384 KiB; reconcile
body 640 KiB and packet 896 KiB. Node original 64 KiB, receipt 224 KiB,
reconcile body 128 KiB and packet 560 KiB; complete peer carrier 320 KiB.
Actual maximum legal fields, PQ encryption and nested exact recovery must be
measured before availability. Unknown padding is not a size fixture.

Each Owner/device authority epoch has at most 64 live reviews, 128 cached reads
with a 300-second lifetime and 128 profile requests per minute. Saturation
refuses new work while preserving exact unknown mutations, permanent removal
history and replay floors. No expired read cache or eviction is a fresh action.

Old Hub 404, absent/false capability or unknown revision means unsupported;
new App shows unavailable actions and never falls back to legacy topology,
raw writes, copied identities or a different deployment. Old App keeps its
existing Join/directory behavior; old directory/wire fields are unchanged.
Old Node cannot consume a new manual delegation: new Hub requires that exact
Node profile before completing it, and cannot downgrade its evidence. Future
migration must preserve identities, keys, epochs, deny/provenance and original
receipts, and refuse an old writer opening unsupported managed state.
No schema number or software release is allocated by this draft.

Required gates are M1 fresh G1 -> named G2 creation + exact D add and lost-response
retry; M2 one original SID/Endpoint/key in two selected scopes; M3 D-G1 removal
without changing A/B/C or D-G2; M4 deny across literal Join/new Attempt/restart;
M4 additionally proves manual activation takes OWNER control, finite manual
expiry cannot fall back to permanent default, and pending re-add cannot clear
an old deny before exact Complete. M5 default-policy revoke with G2 continuing **past the actual lease-renewal
boundary and Node/MCP restart**; M6 last-group removal retaining identity/key/
Thread/history; M7 real Owner/Node revoke fencing all dependent Groups; M8 old
request/reply/selection/outbox never borrowing another Group/Network/Link.
Include concurrent add/remove CAS, shared-principal Endpoints with broader grants
and legacy/global-mutation bypass negatives, exact old packet
recovery after expiry/revoke, maximum crypto carriers, restore and old-profile
negatives. Deterministic and disposable real TCP/Docker gates precede an actual
App/Hub/Node/four-Thread Runtime scene. Codex TUI cross-thread scheduling is not
Cicada communication. Every product gate is **NOT_RUN** at this shared-code checkpoint;
Windows DPAPI/ACL/physical UI, physical devices and public HTTPS remain separately
attributed. Contract-oracle mutation checks prove only document/inventory safety.

Historical contract-only validation at `e3544d9`, 2026-10-26: the Endpoint inventory/prose checker,
five pure oracle tests (60 rejected synthetic mutations), and the existing
Owner-activation/App-Node/Pair metadata checks pass. Three targeted compiled
legacy wire checks pass with no skips; they check old activation/capability and
local-domain inventory compatibility, not the proposed Group implementation.
Source-specific logs and hashes are retained under
`~/Cicada/.local/evidence/owner-groups-guard-clarification-20261026/`.
The earlier four-test/55-control Owner-control receipt and three legacy wire
checks retain their original source under
`~/Cicada/.local/evidence/owner-groups-contract-20261026T094548Z/`;
the clarification changes no production or legacy-wire input.
No new-profile signature/packet, Store, Docker, App, Node or Runtime execution
is claimed by that historical receipt. Availability stays false pending complete
implementation and same-source security gates.

### Shared Go source phase

`hubaccountwire` exports `OwnerEndpointGroupsReadRequest`, `PrepareRequest`,
`ApplyRequest`, `StatusRequest` and `ReconcileRequest` (each with the
`OwnerEndpointGroups` prefix), their typed bodies, `OwnerEndpointGroupsReview`,
`OwnerEndpointGroupsCAS`, `OwnerEndpointGroupsResult` and the Thread/relation/
Group/scope-action cards. `e2ee.EndpointGroupPolicy` and its `Core()` projection
keep request proofs, persistent Owner policy and delegated Node-key proof in
separate purposes and domains. No legacy verifier accepts their new optional
expiry. Bare capabilities constructed by the DTO factory have both availability
flags false; only the complete configured service advertises true.

The App uses `NewOwnerEndpointGroupsRead/Prepare` with its existing
`AppNodeSession`, `OwnerAppNodeScope`, independent Owner key and trusted time.
`ValidateOwnerEndpointGroupsReview` compares the authenticated review against
the retained typed prepare and exact prepare ciphertext. `NewOwnerEndpointGroupsApply`
takes that same tuple and signs the exact ADD policy only after comparison;
CREATE/REMOVE carry no policy proof. All use existing `SealClientRequest`.
The existing one-packet PQ carrier/wire version stays unchanged. Only this
profile's exact reconcile operation admits its 640/896 KiB bounds; unknown
operations and old routes retain their old bounds.

`NewOwnerEndpointGroupsStatus` derives the operation ID and digest from the
retained encrypted apply request, before any response exists.
`NewOwnerEndpointGroupsReconcile` embeds a bounded exact original and refuses
recursive/different-device originals. Its fresh outer request uses the original
device's current authenticated session/Owner scope; later login does not extend
the old review or reauthorize a mutation. `OpenOwnerEndpointGroupsResponse`
authenticates the Hub and original route; the App then calls
`VerifyOwnerEndpointGroupsResult`, and for an apply receipt also
`VerifyOwnerEndpointGroupsOperation(review, originalApply, operation, expectedHead)`
with its locally approved review. REMOVE requires a non-nil expectedHead from
the authenticated relation card for the same target/decision revision, retained
with pending intent; other actions may pass nil. The REMOVE receipt advances
relation and decision revision exactly once and retains that head's policy
ID/epoch. ADD advances the relation once and keeps the old decision/head until
Node completion. Fresh current cards bind the original operation's Node,
Network and Group; an unresolved operation cannot establish state using
untargeted current cards. Original
receipts and freshly guarded snapshots stay distinct. An absent operation or
OUTCOME_UNCERTAIN never settles pending intent; only a verified terminal original
receipt/no-effect fence does.

The Hub candidate implements schema migration 69, original-registration references,
Owner review/nonce and operation ledgers, exact sealed-response transactions,
Node describe/key/renew/reconcile handlers and per-Endpoint source Guards. It
reuses the retained Owner, Node, Principal, Endpoint, candidate and binding;
registration renewal creates no business authority. The configured service advertises implementation availability after the
integrated Core/CLI deterministic gate; current encrypted Owner, Node and
per-Endpoint Guards still decide every operation. Node/MCP
and App consumers have separate source attribution and validation; these Hub
results do not establish M1–M8 or native Runtime behavior.

Status/reconcile query completion is separate from the original outcome:
COMPLETED plus OUTCOME_UNCERTAIN finishes only that query wrapper and leaves the
original pending intent/ciphertext intact. After successfully authenticating a
replacement account session for the same original actor, the App may replace
only a STATUS/RECONCILE query wrapper and must persist it before sending. This
requires independently authenticated password login, inspection and new account
session authority: both token and session ID change, while the original
Hub/Owner/account/device, keys and every security epoch remain unchanged. It
retains the original business packet, request ID, digest and review unchanged;
the replacement does not settle that original. With the same session it retries
the exact wrapper. A raw transport/authentication error or local timeout alone
never authorizes replacing or clearing business intent. A delayed
old query wrapper can only read the same original receipt or establish its
permanent zero-effect fence, and cannot dispatch original business. Only the
independently opened and verified exact original receipt/fence settles the
original. An empty-Node exception remains limited to an exact-bound, data-free
terminal query result.
Reconcile of a READ/PREPARE carries
its Node ID from the authenticated original body, without a new directory read.
Only the exact original APPLY targetless no-effect fence may settle without an
operation target. Portable Hub checkpoint/export/restore for schema 69 remains
unreviewed and fails closed; reopening the current Store and recovering exact
receipts are separate tested operations.

The Node DTO supplement supplies EndpointGroupsRegistrationAnchor with explicit
OWNER_ENDPOINT_GROUPS_V1/CODEX_LOCAL_DOMAIN provenance, the original private
registration/key/binding/access/lease coordinates and no replacement token.
EndpointGroupsNodeDescribeResult pages exact relation cards and ACTIVE authority
snapshots in a one-to-one correspondence, at most 64 rows/128 KiB. Node-owned
selection/outbox state freezes that full EndpointGroupCurrentEndpoint source,
contribution revision and Owner-control digest; aggregate relation changes do
not replace its original controlling authority. The Node must independently
match its protected native record/UID, original encrypted join receipt and key
before selecting this profile. Availability alone cannot migrate Pair/legacy.

EndpointGroupsNodeKeyResult contains that anchor, exact Owner policy proof and
either the frozen EndpointGroupKeyPrepareResult or the original ACTIVE delegated
grant/head. The challenge binds the projected manifest's issued time to its
observation time, applicable Group/CAS revisions and the exact projected Owner
head/relation/manifest; Node signs those bytes with the existing primitive.
The independent peer-source union allows exactly one default/manual proof per
Endpoint, with separate original Owner pins and no legacy fallback.
EndpointGroupsNodeRenewResult only refreshes original liveness coordinates;
the Node retains its original token. Node request bodies retain the frozen field
sets, no added identity selectors. Only exact node.endpoint_groups.reconcile
accepts 128 KiB plaintext; response/default packet ceilings remain unchanged,
with additional 64/224/560 KiB profile packet bounds. The inventory defines all
new closed Node result field orders. The Hub candidate installs these bounded
Node handlers behind the existing authenticated RPC route; a completed native
Runtime gate remains a separate result.
