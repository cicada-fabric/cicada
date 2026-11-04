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
Hub auth admission/worker/rate controls; cap live prepares per account/device,
retain permanent operation/nonce floors and reject saturation without dropping
an uncertain original. Do not allocate an account-wide exclusive slot which
lets an unauthenticated replacement candidate strand the Owner.

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

## Exact recovery and terminal refusal

`recovery=BYTE_IDENTICAL_ORIGINAL_ONLY`: every endpoint recovers only its
persisted original ID, operation, digest, full sender identity and scope.
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
crypto checks only. Hub/Store carrier implementation is the next checkpoint;
availability must not be enabled before it. Deterministic Store/Hub tests,
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
