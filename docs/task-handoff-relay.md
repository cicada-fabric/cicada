# Sealed Task handoff over one Hub Relay

Ordinary same-Node handoffs use the existing v45 Remote MCP → owner-only Node
socket → single selected Hub Relay path. A shared Node, UID, account label or
workspace is not NativeDirect evidence. No native direct adapter or eligibility
is added. Task IDs, handoff/outbox IDs and signed message IDs remain exact; no
replacement Task is created. The socket dispatcher recognizes only the exact
Task operation, alongside the existing Group operations.

The handoff body is a canonical packet sealed for the receiving Endpoint. Hub
stores signed opaque bytes and bounded responsibility metadata: Group and exact
principals/Endpoints, revision, owner epoch, digest, expiry and immutable Artifact
references. Artifact references do not grant content access. **This change does
not encrypt the existing SharedTask Objective/AcceptanceCriteria or ordinary
TaskResult summary**, which remain existing Hub-plaintext compatibility gaps.
It establishes blindness for the new handoff body, not the complete Task graph.

New proposals require current sender grants, an active Task claim, exact CAS and
owner epoch, current signed route/key grants and required Artifact authorization.
The receiver accepts an exact proposal version under its current claim grant,
current route and Artifact ACL/version. Task ownership, revision/epoch increment,
old-owner fencing and the acceptance/transfer record commit atomically. Expiry
mutation also requires the current receiver Guard. Acceptance transfers
responsibility; it does not stop external jobs or prove native consumption.

A lost proposal response is recovered from the authenticated exact Hub history
before target resolution, sealing or another Relay/proposal POST. Immutable
outbox intent, IDs, sender, Group, recipient, CAS, epoch, deadline, refs and digest
must match. Current original binding/read grants remain required. Historical
metadata can be read after expiry; history is not new delivery permission. A
proposal retry submitted directly to Store also returns only its exact existing
record, including after transfer, without writing the shared guard timestamp.

An exact lost acceptance response returns the original unchanged Task only while
its receiver, original binding, owner epoch, revision, claim key and active lease
remain exact and current authorization/Artifact ACL still pass. The normalized
requested lease (zero means 300 seconds; range 0–3600) must match the original
transfer lease. Changed leases, evolved state, rebound bindings or revocation
fail closed; query history separately. Replay does not renew a lease or write
Task, handoff, event or shared guard state.

`LOCAL_NODE` is retained only as historical compatibility data. New local Task
creation, wake notification, delivery and acceptance of an old PROPOSED record
are denied. An existing TRANSFERRED receipt may be read under the exact current
receiver and pair/Artifact authorization. No local history or receipt is
manufactured, resealed, reposted or signalled. Before every fresh Remote send,
the source ledger is checked independently of the current target Node: an old
local orphan cannot become a second Remote packet after target movement.

Local packet recovery reads an existing private regular database and sidecars
into a private disposable snapshot, preserving committed WAL history. It streams
at most 64 MiB total, checks original file identity/mode/size/hash before and after,
checks snapshot integrity, verifies the ciphertext digest and source signature,
decrypts using existing keys and matches the canonical packet and complete route
to authenticated Hub history. It does not update replay counters, native context,
source SQLite WAL/SHM or delivery state. Missing main files with orphan sidecars,
unreadable/private-path failures, corrupt or unstable snapshots and missing rows
with nonempty WAL are uncertain and fail closed. The latter is conservative:
SQLite can silently ignore corrupt WAL; missing-row fallback requires trustworthy
absence. Scratch files are removed on every return.

## Validation scope

Focused deterministic tests cover same-Node proposal/accept/transfer, exact lost
ACK retries, shared-guard/event/state immutability, CAS/expiry, owner fencing,
Artifact ACL/version changes, current grants and revocation, valid third Endpoint
denial, actual binding/key-grant rotation, changed leases and legacy receipt
recovery. The new `task_handoff_relay_test.go` exercises actual MCP, Unix socket
and HTTP sender paths with nil Control, production receiver claim/authorization
and endpoint decryption, a persisted Hub database/body canary scan and zero
Relay/proposal reposts during recovery. It rejects unknown socket operations and
forged identities before Node crypto/state mutation.

Legacy packet tests use synthetic signed keys/envelopes and an immutable synthetic
Hub history fixture. Both active-WAL and checkpointed readers preserve all local
regular-file hashes/modes; orphan, corrupt-WAL, missing-history and changed
metadata paths refuse delivery. A synthetic Directory move still cannot bypass
the source-history check. Store legacy records are explicitly synthetic fixture
setup; production code cannot synthesize them. No model/provider calls occur.

The focused command uses the pinned offline Go 1.27.1 image/cache:

```sh
go test ./internal/store ./cmd/cicada \
  -run 'TestSealedSharedTaskHandoff|TestSealedHandoffRetryTransferred|TestSealedTaskHandoff|TestTaskHandoff' \
  -count=1
```

Final normal/race, focused vet/build and disposable topology gate outcomes are
recorded against the frozen source manifest in task-local ignored evidence;
intermediate failures retain their own tested source attribution. The unchanged
Relay overlay's four known Monitor failures remain baseline findings. Synthetic
socket/HTTP/crypto checks do not prove Android, real native Runtime consumption,
physical Node behavior, NativeDirect/account eligibility or public HTTPS; those
acceptance layers are not run by these fixtures.
