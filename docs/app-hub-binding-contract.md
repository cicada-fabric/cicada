# Voluntary App / Hub unbinding and one replacement

Contract **`app-hub-binding-v1`** is additive to the account, activation and
Client protocols. It removes only this App's binding to this Hub. It deletes
no account, Owner, Node, Thread or Group. Old six account operations, their
formats, packet wire version 1, software version and Client catalog remain
unchanged. Public availability describes the carrier, not caller authority.

## Closed wire and Go interface

GET `/v2/owner/app-binding/capabilities` returns `AppBindingCapabilities`:
`contract_revision,available,operations,recovery`. The exact four operations
and paths are:

| POST path | Operation | Request | Response |
|---|---|---|---|
| `/v2/owner/app-binding/unbind/prepare` | `owner.app.unbind.prepare` | `AppUnbindPrepare` | `AppBindingChallenge` |
| `/v2/owner/app-binding/unbind/complete` | `owner.app.unbind.complete` | `AppBindingComplete` | `AppBindingResult` |
| `/v2/owner/app-binding/rebind/prepare` | `owner.app.rebind.prepare` | `AppRebindPrepare` | `AppBindingChallenge` |
| `/v2/owner/app-binding/rebind/complete` | `owner.app.rebind.complete` | `AppBindingComplete` | `AppBindingResult` |

The authoritative ordered JSON field inventory is
[`app-hub-binding-contract.json`](../cicada-go/internal/hubaccountwire/app-hub-binding-contract.json).
Go DTOs and constructors are in
[`app_binding.go`](../cicada-go/internal/hubaccountwire/app_binding.go):

```go
NewAppUnbindPrepare(session SessionContext, owner e2ee.PublicIdentity,
    now time.Time) (AppUnbindPrepare, error)
NewAppRebindPrepare(hub HubIdentity, origin, account, owner, previousDevice,
    unbindDigest, newDeviceID string, ownerPublic e2ee.PublicIdentity,
    now time.Time) (AppRebindPrepare, error)
NewAppBindingComplete(originalPrepare []byte, challenge AppBindingChallenge,
    ownerProof []byte, now time.Time) (AppBindingComplete, error)
ValidateAppBindingPreparedResponse(prepare any, original []byte,
    challenge AppBindingChallenge, hub HubIdentity, now time.Time) error
ValidateAppBindingResultTarget(result AppBindingResult, original []byte,
    binding AppBinding) error
ValidateAppBindingChallenge(ch AppBindingChallenge, hub HubIdentity,
    now time.Time) error
ValidateAppBinding(binding AppBinding, now time.Time) error
AppBindingPacketDigest(raw []byte) string
AppBindingHTTPPath(operation string) string
AppBindingContractCapabilities() AppBindingCapabilities
```

Use the existing `SealClientRequest`, `OpenClientResponse`, `NewClientRoute`,
`PreflightRequest` and `OpenRequestAt` helpers. All four use the existing
one-packet handshake epoch/sequence 1; protected account/device/client epochs
are independent fields. Full pinned Hub public identity, canonical origin,
exact route, request ID, sender identity and request-packet digest are checked.
Unknown fields, mixed purposes and cross-device/cross-Hub results reject.
After opening a challenge, validate it against the retained typed prepare and
its exact ciphertext. After opening a result, validate its target against the
retained complete ciphertext and binding. Never reconstruct or reseal pending
packets to make a retry.

`AppUnbindPrepare` carries the current account token and account/device epochs.
The existing account context has no session ID: the Hub resolves that ID from
the token and fixes it in `AppBinding`. No account password is sent here.
`AppRebindPrepare` has no session or token. It names exactly the previous
voluntarily-unbound device and original unbind binding digest, together with
a fresh device ID and new outer public identity. Those previous coordinates
are included in the Owner-signed binding and cannot be replaced by the Hub's
choice of another tombstone.

`AppBinding` fixes purpose, origin/full Hub pin, account/Owner/current Owner
public identity and version, account/credential epochs, exact device/public
identity and epochs, original session ID or disjoint replacement reference,
prepare ID/ciphertext digest and finite issue/expiry. Unbind requires the
original session and empty replacement fields. Rebind requires no session,
new device epochs/version 1, and a distinct previous ID. Existing/revoked IDs
or previously used public keys cannot be reused.

## Owner and device proof

Prepare establishes only a bounded challenge, not any new authority or a
revocation. Complete requires the current original Owner's independent KEM
possession and ML-DSA proof. Reuse `ownerbootstrap.CreateChallenge` and
`CreateProofWithPrivateOperations`/`VerifyProof`; do not invoke Root activation
or change that existing protocol. The proof's manifest operation ID is
`AppBinding.Digest()`, domain-separated by
`cicada/app-hub-binding/binding/v1\0`. It binds both identities, purpose,
previous-unbind reference, full current scope, epochs and deadlines. Its
authority ID is the exact prepare request ID. A proof for initial activation,
another purpose, device or earlier challenge cannot complete this action.
The fresh App must also open and echo the encrypted server nonce, and sign its
complete envelope. No private Owner or device key leaves the App.

Maximum challenge lifetime is 120 seconds, additionally capped by the original
account session for unbind. Fresh request lifetime is 60 seconds. Body/inner/
outer ceilings reuse the additive activation bounds: 192/256/384 KiB;
embedded original prepare and Owner proof are independently bounded at 96 KiB.
Shape/size/canonical checks precede expensive crypto. Reuse the existing bounded
Hub auth admission/worker/rate controls. Prepare is a finite zero-effect cache:
at most 256 records total, four pending records per candidate device and eight
pending replacement candidates per previous tombstone. Expired rows are deleted
inside a writer using parsed UTC deadlines, including the exact deadline.
Prepare response replay is available while its cache row is retained; it is
not a permanent large-packet recovery guarantee. Its maximum TTL exceeds fresh
request lifetime, or is capped by the original unbind session's expiry, so an
expired original cannot be newly admitted after eviction. There is no permanent
anonymous prepare floor and no account-wide exclusive candidate slot.

Completion ID/digest/nonce floors and exact receipts are permanent, with one
terminal complete per binding digest. After any terminal result, a different
complete ID or ciphertext for that binding refuses without adding another
receipt. Only an admitted historical Owner proof, or the exact current retained
Root public identity/version for a missing prepare, may allocate a terminal
refusal. A caller's self-signed substitute Owner cannot allocate permanent
records. The completion ledger has a hard ceiling of 16,384 records and 64 MiB
of receipt/public-identity bytes; saturation refuses before commit and preserves
the uncertain original. No completion receipt, tombstone or retired key/epoch
floor is deleted to make room.

## Atomic unbinding and historical provenance

The App must reconcile all older uncertain mutations before preparing unbind.
Server serialization remains authoritative: each late old request must repeat
its active device/epoch guard inside its writer transaction. Work committed
before unbind retains its original result; work whose authorization follows
the unbind commit is refused. A pending read or displayed card grants nothing.

One unbind writer verifies the live account/session, exact self device and
Client CAS, current account/credential/restore scope and active original Root
and proof. It seals and durably stores the exact result atomically with:

- permanent account-device REVOKED and device-epoch increment;
- Client-device REVOKED and session-epoch/version increments;
- revocation/cancellation of this App's sessions, access and outstanding
  authorization attempts/grants, without changing other Apps;
- an Owner-proved voluntary **UNBOUND** tombstone with its exact full scope,
  proof and post-unbind Client version/epoch.

Any sealing/SQL failure rolls back the entire transaction. The account,
credentials, account/global epochs, Root key/state and independent Node/
Thread/Group identities and policies stay intact. This is not a reset, Owner
transfer, deletion or security revocation.

Client's frozen state enum stays ACTIVE/REVOKED. A narrowly checked historical
Node/provenance source may accept the dedicated UNBOUND tombstone only if full
Hub/account/Owner/device/public/Root-key coordinates, exact post-unbind Client
version/epoch and current account/restore/Root scope match. Ordinary App,
new enrollment/approval and management guards remain ACTIVE-only. Never allow
REVOKED generally. Generic security revoke on an otherwise matching voluntary
tombstone atomically marks **SECURITY_REVOKED** and increments Client epochs/
version again, permanently stopping the historical exception. Existing Root/
Node/key security revocation retains its original broader fences. Real Node
heartbeat and current Group cryptographic traffic are required to qualify
independence; unchanged DB rows alone are insufficient.

In the bounded Hub composition the existing liveness endpoint is
`POST /v2/relay/nodes/{node_id}/heartbeat` with a Node bearer and strict JSON
body (`{}` preserves Worker status). It returns 204 when accepted. Both this
Machine-heartbeat writer and the other bound liveness writer repeat the
dedicated tombstone's current historical-source check inside the transaction
before updating liveness. UNBOUND preserves the independent Node; its later
SECURITY_REVOKED marker refuses the write, and the public Machine-heartbeat
route returns its existing 401 unauthorized result without changing timestamp,
status or capabilities. Existing sources without this protocol's tombstone
keep their prior behavior. `node.binding.status` is a supported encrypted Node
status operation; `node.heartbeat` is not part of this bounded RPC composition
and must not be used as evidence of heartbeat success or revocation.

## Exact recovery and terminal refusal

`recovery=BYTE_IDENTICAL_ORIGINAL_ONLY`: recovery matches only the
persisted original ID, operation, digest, full sender identity and scope.
The permanent recovery guarantee applies to complete receipts. An expired
prepare's zero-effect challenge may have been evicted; that absence settles
neither an uncertain complete nor the remote App binding.
The App retains exact prepare/complete packets and the original device key.
After self-fencing there is no fresh mutation/status packet or session needed
to obtain the exact already sealed completion receipt. Changed bytes, another
ID, another sender or a different operation cannot borrow it. Returning a
historical receipt never dispatches an action, revives a device or renews a
session, lease, proof or grant.

Complete results have states `UNBOUND`, `BOUND_ZERO`, or `REJECTED`. A rejected
original uses only the closed error codes `EXPIRED`, `NOT_ADMITTED`,
`STALE_SCOPE`, `OWNER_REVOKED`, `DEVICE_INACTIVE`, `ALREADY_REPLACED`,
`RESTORE_FENCED`. Its signed/sealed result binds the exact complete packet and
binding digest and is committed with a permanent no-effect fence. A valid
historically authenticated expired/not-admitted complete can therefore settle
its original without an unsigned-403 retry loop. It cannot be admitted later.
Unauthenticated/malformed input receives no authority or forged terminal proof.
An accepted complete whose reply was lost always recovers its original bytes.

Offline, unavailable/old Hub, timeout, missing row or absent receipt never
means remotely unbound. Keep local pending state and the original packet/key.
Restore and changed epochs may not readmit an old original or recreate its
rights; a retained historical response stays historical. Missing restored
receipt/floor evidence is not a success or a fabricated no-effect proof.

## One zero-privilege replacement

Rebind is available only for the named voluntary tombstone, with at most one
fresh replacement completion per tombstone. Exact retries return its original
receipt; concurrent different candidates/IDs cannot produce fanout. Recheck the
current Root, account/credential/restore epochs, tombstone and fresh device/key
inside the completion writer. Revoked/superseded security provenance refuses.

Successful `BOUND_ZERO` registers only the new account/Client identity. It
creates **no account session, Node-status lease, management grant or transferred
business authorization**. This managed zero-access source must explicitly fence
the legacy `appLease == nil` unrestricted path. Ordinary login follows, then
the existing Owner management flow reads/reviews current scope; any later
authority requires its own current Owner proof. Login alone does not grant Root.

The App coordinates its bounded encrypted candidate slot, old-generation
read-only records, terminal local fence and atomic candidate promotion after
verified completion. This protocol adds no third vault key purpose and does
not silently discard unknown work or old recovery keys. The retained original
Owner signer is preserved; old device IDs/keys are never resurrected.

## Qualification boundary

The first shared checkpoint supplies Go codecs, closed inventory and synthetic
crypto checks only. The following Hub checkpoint adds migration 71, the four
HTTP carriers and independent account-auth availability without Control.
Deterministic Store/Hub tests,
actual App/Hub/Node independence, sole-Owner replacement and disposable Docker
keep separate source-specific results. Android, real native Runtime, physical
Windows and public HTTPS are not qualified by codec tests.

The shared-code producer ran the complete `internal/hubaccountwire` package
with Go 1.27.3, existing offline modules and umask 0077: **103 top-level / 261
terminal PASS, 0 FAIL, 0 SKIP**, package 4.960 seconds. This includes the new
real synthetic Owner KEM/signature roundtrips, exact original-response binding,
typed expired rejection, immutable old-unbind replacement scope and closed
field/operation inventory checks, plus the existing account/activation/family
regressions. The test proves codecs, not Store acceptance or Node independence.
The exact command, dirty-source manifest based on
`55fb1754f2962ad21e59e56bc662e4a72a56f165`, log hash and later commit receipt are
under `/home/zyf/Cicada/.local/evidence/v01-app-binding-wire-20261104-01/`.
Hub carrier, App integration and disposable Docker remain NOT_RUN at this
first checkpoint. No real key, state, service or deployment was changed.

### Hub producer checkpoint, 2026-11-04

Migration 71 records the finite prepare cache, immutable complete receipts,
Owner-proved UNBOUND provenance and one BOUND_ZERO replacement source. Its
required tables, uniqueness index and immutable triggers are checked by the
existing startup migration inventory; missing permanent objects fail closed.
The trusted Store input `HubAppBindingInput.Now` is sampled after acquisition
and verification of the SQLite writer guard. It is a deterministic fixture
seam and trusted process clock, not an HTTP parameter or production clock flag.

The Hub producer ran the four-package scoped command recorded in
`qualification.json`: **85 top-level / 198 terminal PASS, 0 FAIL, 0 SKIP**.
Package elapsed times were Store 63.929 seconds, Server 27.929 seconds,
Hubauth 0.007 seconds and shared wire 0.693 seconds. Real synthetic PQ packets
exercise seal rollback, concurrent original replay, one replacement winner,
zero sessions/leases/grants, retired-key refusal, exact cold recovery,
authenticated expired/missing-prepare refusal, changed-ID proof replay with
no new floor, forged fake-Owner refusal with no permanent allocation, parsed
fractional/exact deadlines, quota expiry, current Root/device epoch fences,
restore retained-pending versus missing-evidence behavior, absent writer guard
and absent permanent schema objects. The real loopback HTTP carrier test also
proves separate ordinary login and management bootstrap without transferred
business authority or reopened initial Root activation.

Existing LocalDomain policy independence for an inactive creator App remains
unchanged. Only this protocol's dedicated tombstone adds the full current
UNBOUND/security-revoked fence to that historical path. The new Store test
checks authenticated Node-policy reads before and after voluntary unbind,
then a fresh refusal after generic security revocation. These Store fixtures
do not qualify the actual TLS heartbeat or current Group end-to-end traffic.

The first development regression run retained five failures: two exposed the
new blanket LocalDomain guard's conflict with the existing independent-policy
contract, and three exposed explicit migration expectation maps ending at 70.
The second run retained only the three migration expectation failures. The
scoped guard correction and six expectation-map updates are in this same
checkpoint; the complete final scoped command above passed. Original logs are
retained with hashes under
`/home/zyf/Cicada/.local/evidence/v01-app-binding-hub-20261104-03/`.
Its source manifest identifies the dirty tree based on
`bb08031766be112e350ed6bdeda902c3c2e79ad9`; the later commit receipt identifies
the committed checkpoint separately. Qualification SHA-256 is
`2585f5d207cfc423328042ec5033b225f7f211a65e87512b61048a9cf6b54c66`.

Root-owned App/TLS/Node heartbeat/current Group cryptographic acceptance and
the disposable Docker gate remain **NOT_RUN by this producer**. Android, real
native Runtime, physical Windows and public HTTPS remain unqualified here.

### Actual heartbeat writer closure, 2026-11-04

The follow-up checkpoint adds only this protocol's existing tombstone check
to the two existing bound heartbeat writers, within each original write
transaction. It adds no schema or RPC. The exact producer selector in
`qualification.json` passed **18 top-level / 35 terminal tests, 0 FAIL,
0 SKIP, exit 0**: Store 17.712 seconds and Server 4.481 seconds. The real
no-Control loopback HTTP test uses the supported Relay heartbeat endpoint and
observes 204 before unbind, 204 afterward, and 401 after security revocation;
the refused attempt changes no Machine projection. Store tests cover both
writers, no clock sampling after refusal, legacy sources without a tombstone,
and preserved timestamp precision. All AppBinding producer regressions also
pass in that selector.

Evidence is under
`/home/zyf/Cicada/.local/evidence/v01-app-binding-heartbeat-20261104-02/`.
The source manifest records the dirty tree based on
`f72fdad692f3b7d77398a927063cdcbca7c1c0d7`; qualification SHA-256 is
`28e7ecd66270ddc51b1cd10b4efa36cfe6fdc217b1f4895c1845bcc359bf920a`.
Root-owned Core/TLS retry and Docker/Group end-to-end gates remain separate.
