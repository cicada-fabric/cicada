# Exact Node TLS authority and offline installation — D1

D1 adds a trusted offline library cycle for a Node TLS leaf: a dedicated Owner
approval, persistent serial/epoch reservation, signing outside the Store
transaction, verified local staging, a NodeControl install ACK, and single-ACTIVE
Hub activation. Strict Hub ingress requires the current Store authorization in
addition to the operator's TLS configuration. A valid CSR, CA signature,
device-code approval or bearer credential does not authorize this cycle.

This is a library and strict-ingress checkpoint. Production startup does not
automatically invoke the installer or its floor checks; runtime reload,
unattended renewal, general remote enrollment, CLI and Owner approval UI remain
PARTIAL or unimplemented. The Client's existing 55 operations, encrypted wire,
independent repository and application E2EE are unchanged. B's CSR primitives
and C's leaf primitives retain their independent source/evidence attribution.

## Public library contract

All Store reservation and local maintenance methods are trusted offline entry
points. They are not exposed through Node bearer upload, general Node RPC,
model tools or public management operations. New deployment CA/key generation
and real key rotation are outside D1. Root/issuer trust and local Owner trust
come from independent explicit local procedures.

| Entry point | Result and mandatory meaning |
| --- | --- |
| `LocalTLSInstaller.Prepare(TLSPreparationRequest, at)` | Fresh dedicated B TLS key, exact CSR and local preparation; returns `TLSPreparedCandidate`, including `LocalAcceptedTLSEpochFloor`, the independently retained local floor. |
| `Store.ReserveNodeTLSCandidate(NodeTLSCandidateInput)` | Current-authority transaction reserves serial, next epoch, exact immutable candidate and grant nonce; returns `NodeTLSAuthoritySnapshot`. Reservation grants no signing or ingress permission. |
| `e2ee.SignOwnerTLSLeafGrant(identity, claims)` | Canonical dedicated Owner proof for the exact reserved `OwnerTLSLeafGrantClaims`. The Owner identity/private key is independently held. |
| `Store.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput)` | Verifies exact Owner proof and current authority, then durably changes RESERVED to ISSUING before signing. |
| `Store.CommitNodeTLSLeaf(NodeTLSAuthorityActionInput, leafPEM)` | Strictly verifies the public leaf and exact current approval in a new transaction; commits SIGNED. Same exact DER retry returns the persisted certificate. |
| `Store.IssueNodeTLSLeaf(NodeTLSLeafIssueInput, TLSIssuer)` | Convenience Begin → existing C signer outside the transaction → Commit; returns only committed public material. Interrupted/failed in-flight issuance burns the reservation. |
| `LocalTLSInstaller.Stage(snapshot, issuerChain, root, hubTrust, at)` | Verifies independent trust, preparation, key separation, exact grant/CSR/leaf/chain and disk key match; durably stages immutable private materials and returns a dedicated NodeControl-signed ACK. It does not activate transport. |
| `Store.RecordNodeTLSInstallAck(NodeTLSInstallAckInput)` | Rechecks current authority and actual NodeControl signature; commits INSTALLED. |
| `Store.PrepareNodeTLSActivation(action, nonce)` | Returns exact `NodeTLSActivationClaims` for the current INSTALLED row. This read does not activate it. |
| `e2ee.SignNodeTLSActivation(identity, claims)` / `Store.ActivateNodeTLSGrant(NodeTLSActivationInput)` | Independently approved HubControl key signs; the Store verifies it and atomically activates the new leaf while revoking the previous ACTIVE leaf. |
| `LocalTLSInstaller.Apply(ACTIVE snapshot, at)` | Independently confirms the Hub Store's current committed ACTIVE row, verifies exact HubControl receipt and staged ACK, advances and persists the independent floor/receipt, then atomically publishes one active config reference. |
| `LocalTLSInstaller.LoadActive(at)` | Checked offline loading primitive: verifies floor, active reference, signed receipt, independently confirmed current Hub ACTIVE row, current local trust and immutable staged materials. D1 product startup is not wired to it. |

`NodeTLSAuthorityActionInput` contains exact request, Node, credential digest and
expected row version. Snapshot material is public: typed claims, CSR, issuer
chain/root, committed leaf, grant, ACK and activation proof. Neither TLS nor
issuer private material enters Store. `NodeTLSLeafParameters` converts validated
fixed claims to C's typed exact leaf parameters; it provides no authorization.

`GetNodeTLSAuthorityReservationLocal` is offline inspection only.
`MarkNodeTLSLeafUncertainLocal` burns an interrupted ISSUING row;
`RevokeNodeTLSGrantLocal` uses row-version CAS and preserves serial, epoch and
nonce history. No recovery method silently reuses an uncertain serial.

## Proofs, identity tuple and trust

The fixed, independent signature domains are:

- Owner grant: `cicada/node/tls-leaf-grant/v1\0`.
- Node staging ACK: `cicada/node/tls-install-ack/v1\0`.
- Hub activation: `cicada/hub/tls-activation/v1\0`.

Proofs use the existing CIRCL ML-DSA-65 identity signing implementation and
canonical typed JSON, bounded by `MaxNodeTLSProofBytes` (32 KiB). Unknown,
duplicate, reordered/noncanonical, trailing or multiple JSON values are
rejected. `NodeTLSAuthorityDigest` is lowercase SHA-256 of the exact canonical
wire, including its signature; it is not a key identity or grant by itself.
Verification requires an independently trusted expected signing identity and
trusted time. A bundle's public key never supplies trust.

| Owner grant fields | Exact scope |
| --- | --- |
| Request, Hub, Node, Owner, Owner key and Client device IDs/versions | Current ACTIVE Owner/device authority, including independently registered Owner public trust. |
| Owner binding, credential digest/version, NodeControl key/version/epoch/binding version, HubControl key/version | Current Hub+Owner Node connection tuple; separate from Network/Group membership and native SessionBinding. |
| CSR DER hash, SPKI DER hash, node/clientAuth role, exact lowercase DNS | The approved dedicated TLS key and CSR, not a self-attested business identity. |
| Issuer signing SPKI hash, issuer/root certificate hashes and explicit generation | The exact independent issuer/trust generation; issuer certificate renewal under the same signing key does not reset serial history. |
| Reserved serial, expected floor and next TLS epoch, exact leaf validity | Serial and epoch are fixed before Owner signing; leaf validity is at most 24 hours. |
| Hub SPKI pin, Hub trust anchor hash, PQ origin, application origin, fixed application protocol/profile | Exact transport destination and logical application origin. Hub peer DNS must match the selected PQ origin. |
| Grant issue/expiry times and independent nonce | Exact one-purpose grant freshness and durable replay identity. |

Times are RFC3339 UTC whole seconds, with no offset/fractional alternative;
expiry is exclusive. The grant ends no later than the leaf; ACK ends no later
than the grant; activation ends no later than the ACK. Serial is nonzero positive
128-bit value encoded as exactly 32 lowercase hex digits. Digests and nonce are
fixed lowercase 32-byte hex. Integer/serial overflow fails closed.

`NodeTLSInstallAckClaims` embeds the complete grant claims, exact signed grant
digest, immutable initial reservation version (1), exact leaf DER hash, its own
times and nonce. It is signed by the current independently approved NodeControl
application key. It attests verified local staging, not model consumption or
active runtime use. `NodeTLSActivationClaims` embeds the complete ACK claims and
exact ACK digest, resulting activation row version, times and nonce; it is
signed by the current independently approved HubControl application key. An
activation signature alone does not commit the Hub Store transaction.

The Node separately verifies its locally installed ACTIVE Owner trust through
`GetNodeOwnerKeyTrustLocal`, current local NodeControl/HubControl binding and
its own NodeControl identity. The local trust record version is distinct from
the Hub Owner key version and is not substituted for it. TLS install never
resets application identities, Endpoint keys, ratchets, replay counters, native
sessions or the local writer.

## Durable state and crash semantics

```text
RESERVED → ISSUING → SIGNED → INSTALLED → ACTIVE
    │          │          │         │        │
    └ CANCELLED└ UNCERTAIN └─────────┴────────┴ REVOKED
```

Schema 56 adds the local D1 authority, epoch-floor, issuer-serial-floor,
independent nonce and retained application-public-key ledgers. The migration is
incremental from this worktree's schema 55; Main and Client schema are separate.
The database enforces at most one ACTIVE per Hub+Node. There is no authorized
overlap period or SPKI-only substitution.

Reserving or signing a replacement does not revoke the previous ACTIVE leaf.
That leaf remains admissible while its proof/time and current business authority
remain valid, even when reservations have advanced the burned epoch floor.
Failed, cancelled or UNCERTAIN replacement issuance does not revoke it. Only
the committed activation transaction replaces it; revocation, expiry or current
authority changes can independently deny it.

Serial floors are keyed by **issuer signing SPKI**, never merely issuer
certificate digest or generation. TLS epoch floors are keyed by Hub+Node and
survive Owner rebind/revoke. Reservation, candidate digest, nonce consumption
and both floor updates occur in one transaction. Same request/exact candidate
is idempotent; an altered candidate, stale floor or mismatched CAS conflicts.
Permanent reservation capacity is 100,000 and nonce capacity 300,000; reaching a
cap rejects new work rather than clearing tombstones. Cancellation/revocation
does not free a consumed serial, epoch or nonce.

Database triggers prohibit reservation, nonce, floor and retained-key deletion,
candidate/nonce/key mutation, changes to evidence after it is set, and floor
rollback or namespace mutation. Reads check the immutable candidate digest,
retained floor bounds and exact purpose/request/digest nonce ledger entries;
signed proof bytes alone do not replace those independent records.

Each signing admission, commit, ACK, activation and current strict admission
rechecks Owner, Owner key, device, credential, binding, NodeControl/HubControl
versions, proof/time and independently known application keys. Revocation or
version changes between phases reject later transitions and ingress. The
issuer signs outside SQLite and no uncommitted leaf is returned as an accepted
result.

An interrupted ISSUING operation is UNCERTAIN. Its reserved serial and epoch
remain burned; retry cannot generate another certificate under them. ML-DSA
signatures may vary, so re-signing identical input is not exact DER idempotency.
Once SIGNED is committed, retry returns that stored certificate. New recovery
uses a fresh request, higher floor and a new exact Owner approval.

## Application-key separation

The shared helper is
`pqtls.CheckTLSCSRApplicationKeySeparation(csrPEM, TLSCSRParameters, knownSigningPublic)`.
It first verifies B's complete strict CSR, then uses accepted OpenSSL 3.5.9
`d2i_PUBKEY_ex`, `EVP_PKEY_get_raw_public_key`,
`EVP_PKEY_new_raw_public_key_ex("ML-DSA-65")`, `i2d_PUBKEY` and `EVP_PKEY_eq` for
official SPKI/raw-public normalization and actual public-key comparison. It
imports no application private key and writes no file. There is no custom ASN.1
encoder or comparison of unlike raw/SPKI hashes. The official raw-public import
supports ML-DSA, and key equality has separate match/different/unsupported
results. [OpenSSL raw public keys](https://docs.openssl.org/3.5/man3/EVP_PKEY_new/),
[key comparison](https://docs.openssl.org/3.5/man3/EVP_PKEY_copy_parameters/).

An inventory has 1–1024 raw ML-DSA-65 public keys of 1952 bytes each. Only an
actual EVP comparison result of 0 permits distinct keys; result 1 rejects reuse
with typed `ErrTLSApplicationKeyReuse`, and negative/unavailable comparisons
reject with typed `ErrUnavailable`. Empty, malformed or oversized inventories
reject with `ErrConfig`; strict CSR/profile errors retain their existing typed
classification. Errors expose no matching position, foreign Owner, key ID or
key bytes. Default/CGO-off/unsupported targets return typed `ErrUnavailable`;
they have no alternate crypto or successful fallback.

`TLSIssuerSigningSPKIHash(chainPEM)` extracts the actual first certificate's
ML-DSA-65 public signing-key hash so a caller cannot assign a fake serial
namespace by editing `TLSIssuerProfile.SPKIDERHash`. It accepts a strict bounded
one-to-four-certificate PEM envelope, fully consumes the first certificate DER
using official `X509_new_ex` plus `d2i_X509`, and exports its public key with
`i2d_PUBKEY` before hashing. OpenSSL 3.5.9 has no `d2i_X509_ex` function. Malformed
envelopes/first DER return typed `ErrIssuer`; a wrong key type returns
`ErrProfile`. This is public-key extraction only: it does not validate CA
status, signatures, complete chain, purpose, independent trust or time. Those
checks remain mandatory in C's `ImportTLSIssuer`/`InspectTLSLeaf`. Reserve,
commit and Node verification compare the actual key hash with the exact signed
issuer tuple; caller-authored profile fields alone are insufficient.

`TLSIssuer.Profile(at)` revalidates the actual opaque imported issuer before
signing. It serializes with `IssueTLSLeaf`/`Destroy`, checks the live key and
role, and reuses C's existing strict issuer import operation for the actual
issuer/root/SPKI tuple and validity intersection. Temporary private DER is
cleared; the result contains no private material or export capability. The
issuance wrapper compares this actual handle tuple with the exact Owner grant
before calling the signer. A zero/destroyed/wrong-purpose handle or expired
chain cannot provide an accepted public tuple.

The Hub builds its bounded inventory itself in the current transaction, across
retained current, pending, expired, retired and revoked application public key
records and historical public snapshots/manifests. This includes Owner,
Client/device, Endpoint, NodeControl and HubControl signing keys, plus retained
known legacy contact/directory keys. The D1 public-key tombstone ledger retains
keys observed during authority mutations. No caller-provided public list
authorizes Hub enrollment; exceeding the complete unique-key capacity fails
closed without truncation. Historical inventory scans also fail closed above
8192 records, 64 MiB total encoded material or 4 MiB for one record.

`LocalTLSInstaller.KnownApplicationPublicKeys` is a mandatory **trusted local
maintenance integration** callback. It must read the complete independently
retained local application-public inventory, including all local Endpoint keys
and retired/revoked Owner, NodeControl and HubControl keys, and fail if it cannot
establish that inventory. The installer additionally includes the current
independent Owner/NodeControl/HubControl keys automatically. The callback is
not a remote caller's or bundle's list; its completeness is an explicit trusted
integration responsibility. All entries must have the required raw key shape;
the installer deduplicates exact public bytes before applying the 1024 unique
key cap, so repeated current keys consume no extra capacity. The helper cannot discover a key never disclosed
to the relevant authority or recover a public key already lost/deleted before
D1. Those limits remain; it does not claim universal proof of every private key
on a host.

## Private installation, quarantine and rollback

StateRoot and WriterRoot are pre-existing private real directories. Prepare,
Stage, Apply and checked Load acquire WriterRoot exclusive and Node
`AcquireMaintenanceExclusive` locks; live Agents/writers cause `ErrBusy`.
Recovery checks cover Node and WriterRoot external recovery registries and
internal pending markers. They run before locking, after both locks and before
every installer write. Any quarantine, malformed marker, pending sibling
WriterRoot registration or inspection error fails closed; this installer never
clears recovery quarantine.

The installer refuses symlinks, unexpected path types/owners/modes, path escape
and nonprivate material. Preparation and epoch paths are under an independently
private TLS directory; every epoch uses fresh immutable files created O_EXCL.
Directories are 0700 and material/manifest/config files 0600. Files and directory
entries are fsynced, reread and reverified. `pqtls.NewClient` initializes the
official certificate/private-key match check without dialing the network.

All material paths in an active config point to one staged immutable epoch.
Apply persists the floor/receipt under separate WriterRoot before replacing
one regular active config by atomic rename. It never overwrites several PEMs
in place. Failure before activation preserves the old active bytes; a failure
after Hub activation may stop transport and never reinstates a revoked leaf.
If floor advances before the active reference publishes, normal checked loading
rejects the mismatch; only the same exact signed activation may complete repair.

Burned intermediate Hub reservations can leave the next approved epoch above
the Node's last installed floor. Advancing across them requires the independent
exact Owner grant and trusted confirmation of the Hub's **current committed
ACTIVE** tuple, as well as the exact HubControl receipt. A bundle's own
`State="ACTIVE"` label is not that confirmation: the activation proof can be
signed before the Store activation transaction commits. No such repair permits
a lower/equal conflicting epoch or restoration of a revoked configuration.

`LocalTLSInstaller.CurrentActiveAuthority` is a mandatory trusted offline
callback for Apply and LoadActive. It must independently read the Hub Store's
actual current ACTIVE row, never echo the supplied snapshot or infer commitment
from its signed receipt. Apply compares state, versions, the complete claims,
proofs, certificate hashes and public materials with that row before its floor
and active-reference writes. Missing, failed or absent current-authority reads
return `ErrTLSCurrentAuthorityUnavailable`; an inconsistent row is rejected.
The Hub's grant `ExpectedTLSEpochFloor` records reservation burn history and can
be higher than Prepare's `LocalAcceptedTLSEpochFloor`; those floors are not
interchangeable.

An old Node config or epoch directory fails against an independently retained
higher floor/current Hub grant. Restoring old Hub DB state requires an external
trusted floor/receipt; D1 does not add production Hub startup recovery wiring.
If all authority, receipts and floors are rolled back together, that rollback
is not detectable from the same backup alone and requires explicit recovery
authorization. Calling existing `nodetransport.Load` directly does not enforce
the new floor. These production startup limits are PARTIAL, not recovery PASS.

## Strict ingress and validation boundary

Both Hub ingress classifiers preserve the existing enrolled-path boundary.
Public Client/bootstrap paths gain no TLS enrollment bypass. Strict ingress
derives Node from the actual credential, then requires Store's current ACTIVE
leaf DER hash **and** SPKI hash, TLS epoch and current business tuple. Pins and
operator configuration can only narrow that authority. A chain-valid newly
signed leaf is rejected before activation; a new serial/certificate under an
old permitted SPKI is rejected. Application E2EE and business Guard remain
independently authoritative.

SSE rechecks current authority after dequeue and before each event write, in
addition to idle/time fencing. Its authorization-check linearization point
defines revocation: a completed revocation before that check rejects the write;
bytes already admitted/writing are not a database/network atomic transaction
and cannot be recalled.

Deterministic negative tests cover proof substitution/tampering, nonce/floor/
serial/CAS conflicts, each authority-change window, UNCERTAIN burn, exact DER
retry, single ACTIVE, private install/key/chain/trust/path checks, exclusive
locks, quarantine and activation crash windows. Native adapter tests compare an
actual TLS raw public key against itself, independent CIRCL signing public
keys, complete capped inventories including a matching last entry, malformed
inputs and concurrent native success/error cleanup. Default/CGO-off tests assert
typed unavailability; native cases are not credited to those builds.
The new native tests use `^TestTLSApplication`; B's exact CSR-only and C's exact
certificate-only selectors do not select these additional synthetic CA tests
and preserve their separate checkpoint scope.

Final deterministic/vet/race and disposable real-TCP Docker evidence must name
the final dirty source fingerprint, toolchain, OpenSSL, binary/image and actual
commands/exits. Preliminary checks do not freeze the remaining candidate.
The final D1 validation slice covers the new adapter, D1 Store/installer and
strict Guard in normal/race builds, plus the actual two-process disposable TCP
gate. B/C's full checkpoint suites retain their original evidence; this slice
does not rerun or replace them. Final counts, fingerprints and run receipts live
in Root's ignored report/manifest after source freeze. This contract defines
coverage and makes no unrun gate a PASS. Android/Client, real native Runtime/model,
real arm64 execution, physical devices, public HTTPS, resident deployments,
production CA/key ceremony and unattended renewal remain separate NOT_RUN.
