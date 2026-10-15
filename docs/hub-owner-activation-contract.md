# N2 finite Owner activation contract

Source contract `owner-activation-v1`, 2026-10-15. The protocol helper
checkpoint is `c6107a8`; the subsequent service checkpoint adds schema 62,
local CLI issuance, four encrypted HTTP routes, transactional rejection fences
and the finite App runtime Guard. Scoped implementation tests are recorded in
[validation](hub-owner-activation-validation.md). Integration, native Windows,
Android, public HTTPS and deployment acceptance remain separate.

The Go source in `internal/hubaccountwire/activation*.go` and `reconcile.go`
defines exact field names, order and constructors. All JSON is canonical Go
`encoding/json` output: no whitespace, unknown/duplicate fields or alternate
encodings; byte slices use padded base64. Times are canonical UTC RFC3339Nano;
request/activation IDs are 16 random bytes in lowercase hex; nonces and the
installer secret are 32 random bytes. Public keys and fingerprints retain
their existing representation. No private key or passphrase reaches Hub.

## Compatibility and authority

The protocol revision remains `owner-activation-v1`; its candidate receipt-size
correction is recorded in the implementation checkpoint and manifest.

This additive protocol retains the six frozen `owner-account-v1` operations,
their successful shapes, Client wire 1, `client-hub-v1.6.5`, catalog 55 and
`owner-bootstrap-v1`. It does not change frozen identifiers in place, replace
keys, reset epochs, create a second Owner, or depend on Control inference.
Software version, schema version, protocol revision and Git/image identities
are independent. N2 uses additive schema 62; software
version remains 0.0.5 at the protocol checkpoint.

An account password/session alone cannot create Root, produce Owner proofs,
issue activation material, or authorize an unknown device. Root requires both
the existing Owner KEM private key and signing private key. App identity is
separate from Owner identity and the Hub's three service identities.

`OwnerDeviceGrant` remains the existing canonical, Owner-signed v1
`CLIENT_CONTROL` grant for one exact Hub/Owner/App device/key/fingerprint.
N2 limits its issue-to-expiry interval to ten minutes and consumes its nonce
once, atomically with Root activation and the durable completion receipt.
That expiry is an **enrollment window**, not an expiry of a registered device.

N2 additionally installs a separate, nonrenewable **runtime lease** for exactly
15 minutes from challenge issuance. It is bound by the Owner proof to the same
account/Owner/App identities and epochs. Its exact ordered allowlist is
`["nodes.list","session.capabilities"]`. No wildcard, additional operation,
automatic renewal, write permission, Node enrollment, or general Manager
authority is granted. An ordinary account login is required after completion.
Current account session + current account/device epochs + active Owner key +
runtime lease + existing Guard must all allow each new operation. The App may
display Root proof and finite device authorization, not general management
readiness. N3 App integration is outside this change.

Existing non-N2 devices retain their existing behavior. Re-registering the same
N2 key through the old public registration route must neither remove nor
extend its lease. Lease restrictions apply before dispatch and transactionally
when accepting new Client requests; `session.capabilities` intersects its
reported operations with the lease. A cached result may be recovered after
lease expiry but cannot authorize or dispatch a new operation. Revoked Root,
device, account epoch and restored-state fences are rechecked; a cached receipt
is a historical observation, never current authority.

## Local issuance and two disjoint purposes

`cicada hub activation-issue --purpose initial|legacy-pending
--code-file NEW_0600_FILE [--state-dir DIR] [--cancel-pending]` is a trusted local
operation. Legacy issuance additionally requires `--owner-key-id KEY_ID` and
`--owner-fingerprint FULL_FINGERPRINT` for independent exact review. The output
file contains one secret-bearing, non-URL text item:
`cicada-owner-activation-v1:` plus unpadded base64url of canonical
`ActivationMaterial`. Console output contains only safe metadata; explicit
secret display, if provided, requires a real local terminal. No HTTP/model/Node
issuer exists. Failed output persistence does not silently reissue authority.

Material binds format/version/purpose, canonical origin and explicit loopback
HTTP policy, stable Hub/account/Owner/activation IDs, full Hub fingerprint,
setup version, account epoch, expected Owner public identity, code and
issue/expiry. Maximum lifetime is one hour. The App fetches the existing full
Hub identity and independently matches its fingerprint **before** sending the
material, password or proof. Its fingerprint domain is unchanged from account
v1. The code is neither a URL nor a short user-selected secret.

| Purpose | Issuer prerequisites | Completion writes |
|---|---|---|
| `INITIAL_OWNER_ACTIVATION` | Configured pristine Hub; stable setup IDs already exist; no account credential/public association or Root history. `expected_owner_public_identity:null`. | Credentials, exact login device and immutable pending public association; Root and finite exact App enrollment/lease. |
| `LEGACY_PENDING_CONTINUATION` | Exact persisted account/Owner and immutable `PENDING_PROOF` association; credential already exists; no Root history or revoked key. Material fixes the complete existing Owner public identity and key ID. | Proves that exact Owner and enrolls the reserved App; preserves credential, IDs, public association, existing devices and epochs. |

Legacy material is not a general recovery code. An existing revoked or formerly
active Root is ineligible permanently. It cannot authorize an unknown Owner
public key, change a username/password, resurrect a revoked device ID, or
rebind an existing device key. A new App may be enrolled only using this locally
issued exact legacy authority plus the original Owner's real proof. No login
session is fabricated; ordinary account login follows.

In the inspected schema, `owner_approval_keys_v2` has only ACTIVE/REVOKED
states. The actual `PENDING_PROOF` record lives in
`hub_account_public_association_v1`; its only production writer,
`CompleteHubAccountClaim`, creates that association, credential and first
login device atomically. A legacy Manager with no such persisted candidate
does not become a continuation candidate merely by submitting an unknown key.
Local adoption preserves the exact old Manager/Owner/account coordinates.

## Packet, HTTP and typed API

All new requests and responses use the existing canonical account packet and
ML-KEM-768 / ML-DSA-65 / AES-256-GCM envelope. Outer format and wire remain
unchanged; only the following new operations/types are accepted. Sequence is
1, handshake epoch is 1; account/device/setup epochs remain protected fields.
This epoch does not reset Client session counters. The default frozen Client envelope API
retains its 64 KiB plaintext bound, and the original six account operations
still use it. Only these four additive operations explicitly select the
`clientwire` bounded-body helpers with 192 KiB maximum. The same e2ee/AAD/route
framing and 256 KiB nested-packet bound apply on both seal and open. Larger
N2 status/reconcile bodies cannot enter the ordinary Client receiver because
its default open still rejects plaintext above 64 KiB. Maximum outer/inner packet
sizes remain 384/256 KiB. New protected bodies are at most 192 KiB, original
packets embedded for account reconciliation at most 96 KiB. Activation status
may carry a prepare/complete receipt up to `MaxActivationReceiptBytes` = 128 KiB;
the real PQ prepare challenge exceeds 96 KiB. Maximum-scope Go tests verify the
base64 expansion still fits all unchanged body/inner/outer limits. Oversized input fails
before expensive crypto; existing admission/rate limits continue to apply.

| HTTP POST | Operation | Request | Success response |
|---|---|---|---|
| `/v2/owner/activation/prepare` | `owner.activation.prepare` | `ActivationPrepare` | `ActivationChallenge` |
| `/v2/owner/activation/complete` | `owner.activation.complete` | `ActivationComplete` | `ActivationResult` |
| `/v2/owner/activation/status` | `owner.activation.status` | `ActivationStatusRequest` | `ActivationResult` |
| `/v2/owner/account/reconcile` | `owner.account.reconcile` | `AccountReconcileRequest` | `AccountReconcileResult` |

Constructors are `DecodeActivationCode`, `ValidateActivationHub`,
`NewActivationPrepare`, `ValidateActivationChallenge`,
`NewActivationComplete`, `NewActivationStatusRequest`,
`NewAccountReconcileRequest`; seal/open through `SealClientRequest` and
`OpenClientResponse`. `ActivationPacketDigest` hashes domain
`cicada/owner-activation/packet/v1\0` + exact original packet bytes.
It is distinct from the Store's internal account-v1 packet digest.
`ActivationGrantDigest` is ordinary SHA-256 of exact canonical grant bytes.
`ActivationHTTPPath` owns the new operation/endpoint mapping. After opening a
challenge, use `ValidateActivationPreparedResponse` while the typed prepare is
available. Status/reconcile results require `ValidateActivationStatusTarget`
or `ValidateAccountReconcileTarget` against the actual pending packet before
settlement. `ABSENT` still cannot settle it. `OpenClientResponse` automatically
checks challenge and activation-result request-packet digests.

Prepare contains material, exact Owner public identity, App device ID, signed
OwnerDeviceGrant, operation ID/nonce and issue time. The App's full public
identity is in the signed outer packet. The first valid request atomically
reserves that complete tuple, exact prepare packet/operation/nonce, grant and
account/setup epochs. Changed keys, grant, packet or operation cannot replace
the candidate, including after timeout or restart. Matching concurrent prepares
return the same persisted challenge bytes. The code alone activates nothing.

Challenge contains immutable `ActivationBinding`, the echoed client nonce,
device-encrypted server nonce, exact Owner pairing challenge and finite times.
`ActivationBinding` fixes full Owner and App identities, IDs, origin/Hub pin,
epochs, prepare operation/packet digest, grant digest, exact allowlist and lease
expiry. Its digest is SHA-256 of
`cicada/owner-activation/binding/v1\0` + its canonical JSON. The existing
bootstrap manifest's `operation_id` equals that full digest; `authority_id`
equals the activation ID. Both mappings are verified before Owner private-key
operations. Other manifest scope, expiry and full Owner identity match the
binding. N2 never inserts this authority into the old bootstrap-authority table
or exposes it through the old bootstrap accept route.

`NewActivationComplete` verifies the exact challenge and uses the imported or
generated existing Owner key through `ownerbootstrap.CreateProof`. It echoes
the server nonce, supplies the Owner KEM/signature proof, binding and fresh
completion operation/nonce. Initial completion supplies username/password
(existing password policy); legacy completion requires both to be empty.
The Hub verifies the original fixed grant and device challenge independently.
No database transaction remains open across crypto, HTTP or human review.

## Atomic state machine and retries

```text
local issue -> ISSUED -> PREPARED -> COMPLETED
                  |        |
                  +--------+----> CANCELLED (explicit local replacement)
                  +--------+----> expired (derived; no new completion)
```

Every accepted operation has a durable operation ID, exact packet digest and
original sealed response. Same ID/different bytes conflicts. Nonces cannot be
reused for another accepted operation. Only an exact durable accepted replay
skips request age checks. New prepare/complete/status/reconcile packets have a
60-second freshness limit; proof challenge is at most ten minutes and no later
than material or grant expiry. Rejected completion proof does not activate Root
or consume the code/grant; a fresh corrected operation is possible while the
exact reservation remains eligible. No public reset/replacement exists. A local code replacement also retains the
previously reserved complete Owner/App public-key tuple and device ID; it is
not a private-key-loss recovery or rekey operation.

One completion transaction rechecks current setup/account/device epochs,
active exact human, no Root history, the reservation, candidate keys, grant
nonce, expiry and pending public association; then writes initial credentials
when needed, login device, active Root/permanent Root history, exact enrolled
Client device/proof, finite lease, authority consumption and the sealed receipt.
Any conflict or crash rolls the whole transaction back. A committed response
can be lost and recovered byte-for-byte after restart. Delayed or concurrent
completion cannot create a second Root or renew the lease. A restart preserves
pending reservations. Verified restore advances the existing account fence,
cancels pending N2 authority and disables old leases without changing IDs,
keys, credential or history.

Authenticated terminal refusals persist an operation+digest tombstone in the
same serialization domain as completion. A later copy of the refused packet
cannot commit. Unknown keys, bad signature/code or untrusted origin still get
generic unsigned HTTP rejection. Such HTTP errors, timeouts, busy responses
and process exits never settle an App's pending request.

## Reconciliation and current state

Activation status is a fresh App-signed request against its exact durable
reservation (or enrolled identity). It reports current epoch, Root and lease
state, login requirement and the requested operation/digest's durable outcome.
`COMPLETED` carries its original response packet; `REJECTED`/`CANCELLED` settles
only the exact fenced operation+digest. `ABSENT` is observational and must not
clear an uncertain packet: the original may still be in transit. Status never
issues, renews or reopens authority. Recovery access grants no business read.
An original successful Root/lease receipt does not override current status. Root/device revocation or account/restore epoch fencing
withholds a cached ACTIVE activation response: the original route returns a
fresh authenticated CANCELLED result with current state. Lease expiry alone
permits historical receipt recovery. A status result may still carry an older
COMPLETED receipt while reporting current ROOT_UNAVAILABLE/REVOKED; its outer
current snapshot wins over the embedded historical result.

`AccountReconcileRequest` carries the exact original encrypted packet plus a
fresh operation/nonce. Only the already recorded exact account device can
invoke it, with no still-valid session required. Supported original operations
are login prepare/complete and session inspect/logout. The Hub opens and checks
the original device envelope and all coordinates, even when the request or
session is old. It does not trust an HTTP error supplied by the App.

Under one Store transaction, an accepted original yields `COMPLETED` plus its
exact cached packet; otherwise `REJECTED` durably fences the original account,
device, operation ID and packet digest. The ordinary account write transactions
check that fence before challenge/session/receipt commit. This resolves a
reconcile race with an original still deriving a password: either the original
commit wins or its rejection fence wins. No second session is fabricated.
New status/reconcile response receipts are limited to 128 per device/account
epoch. At capacity the Hub returns busy (HTTP 429) without settling the App's
pending request. Original exact receipt retries and the primary rejection
fences remain recoverable and are never deleted or blocked by this new-read
budget. Account-original rejection and its sealed reconcile response are two
short local transactions: a crash between them leaves the original fenced;
retrying reconcile observes the same terminal outcome and writes its response.

Different bytes under the same operation ID conflict and cannot replace the
original ledger entry. A wrong-password completion can therefore be settled
and retried with a correct password/new operation; an expired session request
can be settled before a new ordinary login. Existing success shapes/routes are
unchanged. Reconcile responses and status are authenticated observations;
they do not restore an expired/revoked session or Root.

## Required evidence

The protocol checkpoint tests strict code/packet parsing, full Hub pin,
candidate/epoch/nonce/allowlist binding, Owner KEM and signing proof, separate
grant, legacy identity preservation, canonical round trips and authenticated
result route/digest binding. These are not server acceptance results.
`python3 scripts/owner-activation-contract.py check` checks the additive
machine-readable manifest and prose; the unchanged Client contract has its own
`python3 scripts/client-contract.py check`.

The server checkpoint must additionally test concurrent prepare/complete,
wrong/tampered Owner proof and grant, unknown or substituted legacy key,
transaction rollback, expiry/cancellation/revocation, both response-loss windows
and reopened Store, original-vs-reconcile races, wrong-password correction,
expired-session re-login, lease expiry and forbidden operations through direct
and encrypted entry points, capabilities intersection, old registration bypass,
schema/restore preservation, and Control-absent HTTP execution. Run isolated
Go/race/vet and immutable-image disposable Docker interop; never use resident
Hub data or real keys. Android, native Windows Runtime/DPAPI, physical devices,
public HTTPS and PQTLS remain independent NOT_RUN unless actually exercised.
