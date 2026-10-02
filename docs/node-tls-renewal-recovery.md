# Node TLS renewal and activation recovery v0.1

This D2.2 checkpoint adds trusted local maintenance coordination over frozen
D1 schema 56. It does not add a migration, issuer key storage, automatic renewal
authority, general RPC, CLI, deployment procedure or hot reload. Schema 57 is
reserved for the separate privacy work. Source attribution must include the
combined Task14, Restore20 and D1 inputs plus the new D2 source fingerprint;
the dirty worktree is not attributable solely to its detached Git HEAD.

## Exact human authorization

Every replacement certificate requires a new D1 `OwnerTLSLeafGrantClaims`
signature by the currently authorized Owner. That signature fixes the exact
CSR/SPKI, issuer signing SPKI and certificate/root hashes, issuer generation,
serial, burned epoch floor and next epoch, validity, Hub origins and peer pin,
and current Owner/device/credential/NodeControl/HubControl tuple. A valid CSR,
Node bearer, application-key pairing approval, install ACK or Hub activation
receipt is not this TLS approval. An old TLS grant only permits its original
exact idempotent operation; it is not standing delegation to renew, change
dates, generate another key or reserve another serial.

The Node keeps its dedicated TLS private key locally. The issuer remains the
separate opaque C issuer supplied to D1. D2 public status and activation results
contain no issuer, TLS or application private key. Production issuer loading,
key ceremonies and additional approval interfaces require separate approval.

## Authoritative local status

`Store.ReadNodeTLSAuthorityRecoveryLocal(NodeTLSAuthorityStatusInput)` accepts
trusted local Node ID and credential digest. One read-only transaction verifies
the current full NodeControl/Owner/device/credential binding, obtains actual
Owner and Client device versions, and reads the permanent Hub+Node burn floor.
Its current snapshot is produced by D1's strict current authority verifier,
including the exact grant, install ACK, activation, certificate/public materials
and permanent nonce entries. It never accepts a caller's snapshot or public-key
inventory as current evidence and never increments RPC admission sequences.

| `CurrentActiveState` | Meaning |
| --- | --- |
| `CURRENT` | `CurrentActive` contains the independently verified committed ACTIVE snapshot at this transaction's authorization point. |
| `NONE` | No ACTIVE row exists; `CurrentActive` is nil. |
| `UNAVAILABLE` | An ACTIVE row exists but its current proof, crypto, validity or retained-key checks cannot authorize it; `CurrentActive` is nil. |

NONE and UNAVAILABLE must fail checked runtime loading. UNAVAILABLE still lets
a trusted maintenance caller inspect the burn floor before preparing a new
exact Owner request. Direct transaction/query failures remain errors; frozen
D1 snapshot validation folds some floor/nonce read failures into typed denial,
which is classified UNAVAILABLE here. Revoked or mismatched
current Owner/device/credential/Control binding rejects the status read itself.

Pending output contains only request ID, state, row version and TLS epoch for
RESERVED, ISSUING, SIGNED and INSTALLED rows. It is progress metadata, not an
approval or proof that a CSR/certificate is valid. It is bounded to 256 rows;
overflow rejects instead of silently truncating. UNCERTAIN, CANCELLED and
REVOKED history stays permanently in D1, outside this pending list. A higher
reservation/burn floor does not invalidate an otherwise current older ACTIVE;
only committed activation/revoke, expiry or current authority changes do so.

Runtime D2.1 separately owns the fresh authenticated read-only status adapter
and checked startup. A production callback must perform that independent fresh
read, bind its nonce and full current tuple, and reject cached or recovered
outbox replies. `GetNodeTLSAuthorityReservationLocal`, a bundle's ACTIVE label
and an old signed receipt do not substitute for a current-authority read.
Fabric-only serving must use a pure Store/state reader, not instantiate or start
Control business services merely to answer a current query.

## Hub activation and durable retries

`Control.ActivateNodeTLSAuthorityLocal(action, nonce)` is a maintenance library
entry point. D1 must already have committed the exact Owner grant, C-issued
leaf and independently signed current Node install ACK. The coordinator checks
Control's actual existing HubControl public identity against the current Store
binding, including its complete public identity, Hub ID and key version. It
then prepares exact Store claims, signs with that independent application
identity, and calls D1's current-fenced activation CAS.

Preparing or signing an activation does not commit it. No prepared proof is
returned as an active result. After CAS, the coordinator independently rereads
strict current authority and compares the complete immutable public result.
The Store row remains authoritative if an output or subsequent current read is
lost: a same request, original INSTALLED version and original activation nonce
can retrieve the original persisted current proof. It never regenerates or
replaces that proof. A different nonce/version, foreign actual Hub identity,
revoked current device or no longer current request rejects the retry. Two
same-intent callers may recover the exact committed winner after a CAS race.

The existing D1 transaction permanently records the activation nonce and exact
proof, revokes the prior ACTIVE and makes one new ACTIVE. No D2 outbox table or
new schema is needed. If the process crashes before activation commit, the row
stays INSTALLED and the previous ACTIVE remains; after commit, recovery reads
the persisted proof. If any required approval has expired, it cannot be widened
on retry: obtain a new exact Owner grant and a new reservation.

## Stopped issuance and controlled installation

1. Stop Hub signing and stop all Node Agents/writers sharing the installed
   StateRoot/WriterRoot. Existing D1 direct issuer callers do not participate in
   a new issuance lock, so a Node lock alone does not prove a Hub signer stopped.
2. Acquire `AcquireNodeTLSAuthorityMaintenanceLocal(StateRoot, WriterRoot,
   NodeID)` using independently installed roots. It obtains real exclusive
   WriterRoot and Node maintenance locks, fails busy for a live Agent/writer,
   and returns an opaque held-lock capability; no bool or skip-lock parameter
   can replace it. Every value copy shares one private mutex, ownership and
   closed state. Closing any copy invalidates all copies; duplicate Close is
   harmless, and nil/zero/closed capabilities cannot burn a row.
3. For one known ISSUING request, call
   `BurnNodeTLSIssuanceUncertainLocal(originalAction, heldMaintenance)`. Current
   binding and exact row version are rechecked in the mutation transaction.
   Only ISSUING becomes UNCERTAIN; original proof and serial/epoch/nonce floors
   remain. The same original CAS may return the already-burned row without
   changing its version. Other states, stale versions, foreign Nodes, closed
   or missing lock capabilities reject. This never resumes or signs issuance.
4. Close the recovery capability before calling the D1 installer, which acquires
   its own exclusive maintenance locks. Prepare a fresh dedicated TLS candidate,
   reserve against the actual Hub burn floor, obtain its new exact Owner grant,
   and complete C issue/commit, stage/ACK and committed Hub activation.
5. Apply only with independent current committed authority and valid local
   trust/materials. D1 durably advances the local floor/receipt before publishing
   its atomic active reference. Burned intermediate Hub epochs may be skipped
   by the new exact active proof; the local accepted floor never decreases.
6. Restart through D2.1's checked loader and lifetime-lock handoff. This library
   checkpoint alone does not replace legacy `nodetransport.Load` in product
   startup. A paused maintenance window is required; live hot reload and
   unattended renewal are outside v0.1.

The Store transaction/current read is an authorization point. It is not an
atomic transaction spanning Hub DB, Node disk and network IO, and cannot recall
bytes already sent. Runtime checks and server current Guards continue to reject
old or revoked authority after changes.

## Restore boundary and acceptance

Frozen Node backup inventory does not yet include D1 `StateRoot/.node-tls` and
`WriterRoot/.node-tls-floors`. Root coordinates that work with the separate
Restore owner; this checkpoint does not occupy Nodebackup paths or claim TLS
backup/restore completion. A restored old signed receipt/floor is pending
evidence, not independent anti-rollback proof. Preserve quarantine, compare an
independently retained floor and freshly verified Hub current authority, and
never lower a floor or clear quarantine based solely on restored signatures.
Rollback of Hub DB, Node receipts and all independent floors together cannot
be detected from the same backup; it needs explicit recovery authorization.

Deterministic tests in the two owned test files cover exact current status,
bounded output, real maintenance exclusion and capability lifetime, actual
HubControl identity rejection, prepared-versus-committed activation, same-intent
CAS competition, exact persisted retries after Store reopen, revoked-device
refusal, UNCERTAIN permanence, and a new exact grant activating across a burned
epoch. Native tests use pinned offline OpenSSL with visibly synthetic private
temporary fixtures and suppress command payloads. A requested native gate fails
when the adapter is unavailable. Default tests record native branches NOT_RUN;
their typed unavailable paths do not prove native execution.

Root owns unified source-fingerprinted default/native/race/CGO-off, vet and
disposable Docker evidence. Source writers do not run independent acceptance.
Android, physical devices, public HTTPS, production CA/key ceremony, real
Runtime/model, other-platform execution and production deployment remain
separate NOT_RUN results. Restore positive acceptance depends on the separate
Root-owned backup/floor integration evidence.
