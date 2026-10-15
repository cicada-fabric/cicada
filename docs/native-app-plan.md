# Native App plan

This plan describes the Windows-first native App inside the CICADA monorepo.
Its Go implementation remains in `cicada-go`; Android is maintained under
`apps/android` with its original history retained. The layout does not establish
native Windows acceptance. “App” is the current product name; older Client-facing wire names,
code and evidence remain attributed to their original contract and source.

## Product boundary

CICADA is operated through three independently distributed components: Hub,
Node and App. A human Owner is an independent authority, not a service role.
Manager handles user intent, management and approval; Advisor may provide
bounded recommendations; Worker performs authorized execution. These logical
roles do not collapse into the Hub or App. The Hub remains authoritative for
identity, encrypted account sessions and server-side authorization. The App
must preserve existing Hub state and Owner keys and must not synthesize grants,
Root activation, Manager authority or Node membership.

The native App is a self-contained Windows target with a Go core and native
renderer. It has no browser/WebView UI target and no browser storage. Private
identity and exact pending protocol state are kept only in the encrypted
application vault. The current Hub account protocol uses the existing
ML-KEM-768 / ML-DSA-65 application envelopes. Transport policy is explicit;
HTTPS is required by default, and HTTP is permitted only when a user/operator
explicitly enables a loopback fixture. A native strict-PQTLS transport is not
implemented or accepted by this plan.

## Checkpoints

| Checkpoint | Scope | State |
| --- | --- | --- |
| N1 — Native foundation | Typed Hub connection and health verification; strict secret-free connection card; explicit transport policy; encrypted-vault identity and exact-packet persistence; existing encrypted claim/login/inspect/logout calls; honest account/Root pending states; native controller contract and deterministic protocol tests. | In progress in the current source checkpoint. See [validation](native-app-validation.md). |
| N2 — Owner proof and finite activation | Reuse imported existing Owner keypairs without replacement; define one-use deployment activation material as a secret-bearing local code (never a URL); implement the server-authorized Root-completion operation and controlled continuation for an already-existing exact Owner/account. Add trusted local-profile resume after restart so an expired bootstrap code is not needed again. The existing account claim alone never activates Root. | Not implemented. Requires an agreed Hub contract and bounded authority design before code. |
| N3 — Authorized live canvas and Node actions | Add live objects only from an authenticated, authorized Hub/Node read path; add explicit guarded Node actions and status reconciliation. Empty/unavailable canvas stays empty; no demo objects are presented as live state. | Not implemented. Requires server-side read/action authorization and durable operation semantics. |
| N4 — Legacy naming and surface retirement | Retire transitional browser and public Client names only after equivalent App behavior, migration and interoperability gates pass. Preserve old wire identifiers and historical evidence attribution. | Not started. |

The authorized Android history-preserving subtree import is complete as
repository maintenance; see the [migration record](repository-migration.md).
It used a nonsquashed Git import and did not rewrite old history. It does not
complete N1 or transfer earlier Android acceptance to the migrated source.

## N1 acceptance boundary

N1 may report success only for the exact tests and targets that pass. It does
not establish native Windows ACL/DPAPI acceptance, strict PQTLS, Android
interoperability, physical-device behavior, public HTTPS deployment, live
canvas authorization, or product/release completion. The validation document
records each result independently. Hub account `PENDING_PROOF` remains distinct
from active Root, and the App may show a ready account session only as account
session readiness; it cannot label that state as activated CICADA ownership.

The N1 restart path currently requires the same unexpired secret-bearing
claim code for an initial claim, or the same still-valid public connection card
for an existing account. Trusted local-profile discovery and automatic resume
without bootstrap material are N2 work. The protocol accepts only the existing
initial-account claim authority; it does not provide Root completion or
existing-Owner continuation.

## N2 independent acceptance matrix

The following are acceptance obligations, not implementation claims. The
independent driver is `scripts/test-native-app-n2.sh`; its initial lane covers
the existing account core with real ML-KEM/ML-DSA/AES-GCM, loopback TCP,
persistent SQLite and separate Hub/App processes inside a disposable Docker
container. It has no Control inference service. N2 rows require the frozen
Hub/App contract and exact implementation commits before they can pass.

| ID | Fault or boundary | Required observation | Initial scope |
| --- | --- | --- | --- |
| N2-01 | Wrong full Hub public key/pin | Connect rejects before secret POST or vault creation | Account baseline |
| N2-02 | Expired finite credential | Local preflight and Hub expiry guard independently reject; no authority change | Account baseline + N2 pending |
| N2-03 | Consumed credential, exact duplicate and changed request | Original packet returns identical durable receipt; changed identity/request fails | Account baseline + N2 pending |
| N2-04 | Concurrent distinct candidate claims | Exactly one durable winner, loser cannot overwrite candidate or account | Account baseline + N2 pending |
| N2-05 | Wrong Owner/account/Hub scope | Server rejects independently of client preflight | Account baseline + N2 pending |
| N2-06 | Missing Owner KEM or signature proof | Account stays usable but Root/Manager remain unavailable | N2 pending |
| N2-07 | Forged/expired/wrong-purpose OwnerDeviceGrant | No enrollment or Manager authority | Existing crypto guard + N2 pending |
| N2-08 | Stale setup/account/device/grant epoch | No new execution and no revival through a cached receipt | Existing account guard + N2 pending |
| N2-09 | Unknown or substituted App device | Password/token/public capability cannot bypass exact enrolled key | Account baseline + N2 pending |
| N2-10 | Drop committed response, unsigned 403, corrupt PQ response | Durable uncertainty fence; only authenticated response settles operation | Account baseline + N2 pending |
| N2-11 | Kill Hub/App process and reopen persistent state | Same IDs/keys and original encrypted packet survive; no duplicate effect | Account baseline + N2 pending |
| N2-12 | Same operation ID with different ciphertext or nonce replay | Reject conflicting request without replacing original receipt | Account baseline + N2 pending |
| N2-13 | Account login versus Root and Control inference unavailable | Claim/login/inspect/logout work; account session grants no Root/Manager | Account baseline; full activation pending |
| N2-14 | Exact legacy PENDING_PROOF continuation | Existing Owner/account/key IDs retained; no second Owner/rekey/revoked Root recovery | N2 pending |
| N2-15 | Trusted profile reopen without expired bootstrap code | Discover encrypted profile; authenticate current epoch before management | N2 pending |
| N2-16 | Vault persistence failure before send | Zero POSTs; fail closed until reopen; no memory-only retry | Existing App guard; N2 pending |
| N2-17 | Two Hub scopes | No key/session/pending-state inheritance | Existing vault guard; N2 pending |
| N2-18 | Windows DPAPI, ACL and GUI | Native execution receipts required individually | NOT_RUN |
| N2-19 | Expired 15-minute App lease, late old completion | Fixed finite lease cannot self-renew; expired/revoked authority cannot be revived by exact receipt recovery | N2 pending |
| N2-20 | Status ABSENT, lost packet and late original arrival | ABSENT preserves uncertainty; only original authenticated receipt or durable operation+digest terminal fence allows replacement | N2 pending |
| N2-21 | Wrong password, then correct password | Authenticated terminal rejection safely fences the failed operation; correct password can begin a new request | N2 pending; baseline recovery gap under review |
| N2-22 | Expired or revoked account session | Safe authenticated reconciliation permits login again; never treats unsigned 403 as final or stays permanently unrecoverable | N2 pending; baseline recovery gap under review |
| N2-23 | Native interaction and visual quality | Smooth, legible real desktop setup/recovery; no secret disclosure in snapshots or error UI | Windows GUI/visual review NOT_RUN |

Each run must record source manifest before/after, dirty status, builder image
ID, test binary hash, selectors, individual exit codes and skips, resource
ownership/cleanup and artifact hashes. No selector match, missing prerequisite,
skip or unimplemented row is a pass. Default baseline success is a scoped
result only; `--require-n2` must return nonzero while complete N2 acceptance is
unavailable. Android, native Runtime, physical device, public HTTPS and native
PQTLS are separate NOT_RUN scopes.
