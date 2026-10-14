# Hub Owner account claim contract proposal

Status: **PROPOSED / review only**. No route, account service, migration, or UI
is implemented by this proposal. The software 0.0.5
[`owner-bootstrap-v1`](hub-owner-bootstrap-contract.md) remains unchanged: it
assumes an existing account and locally issues authority for one exact Root
candidate. This separate flow creates an account from a finite fresh-install
claim. It does not change Client Wire v1, Client contract v1.6.5, catalog 55,
or Android behavior. The existing finite Owner bootstrap and Client grant /
enrollment are implemented separately; claim, password login, account session,
and the same-browser consent bridge below are proposals only. No
account-purpose sealed route or cookie/session mechanism exists yet.
The operation names, payload fields, time limits, and fingerprint encoding
below are review targets, not frozen wire. Exact packet/transcript bytes and
published vectors must be reviewed and frozen before implementation.

The adopted trust boundary trusts the installed Hub build and its physical
administrator. A malicious host administrator is out of scope and the
deploying user's responsibility. The UI may be Hub-served; no separate signed
desktop UI, enclave, or VM is required. The implementation still must keep
secrets out of URLs, logs, debug output, and unintended storage. This adopted
boundary supersedes the independent-UI alternative in the earlier
[security review](hub-owner-onboarding-security.md): UI integrity is part of
the trusted installed Hub, not a separate acceptance blocker.

## Two-page flow

The installer emits the Hub URL and one copyable/scanable claim payload. The
user opens that URL and enters or scans the payload. Page one verifies that the
page's canonical origin and the live Hub's complete public identity match the
installer pin before sending the code. It sends the code only inside the
existing ML-KEM-768 / ML-DSA-65 / AES-256-GCM sealed application envelope,
bound to a new account claim purpose and operation. Remote claims also require
authenticated HTTPS;
plain HTTP is limited to explicit literal-loopback development. HTTPS is
defense in depth, not a replacement for the application envelope. The bounded
response is protected to the generated browser login-device identity. Any
short-lived claim state stays memory-only and cannot authorize ordinary Client
RPCs.

Page two accepts the username, password and confirmation, plus the user's
existing ML-KEM-768 / ML-DSA-65 public identity. It generates the separate
browser login-device identity internally and keeps its private bytes in a
locally protected vault that is not unlocked or derived solely from the
account password; the user does not enter device IDs or keys. Private Owner
PEMs, seeds and passphrases never enter the browser or Hub. Reuse the existing
strict SPKI parser and Go key validation; do not add another ASN.1 parser or
crypto-suite definition.

Keep the user on page two while the state changes; do not add another
registration form. The installer code authorizes only the stable account, its first
`ACCOUNT_LOGIN` device, and a **pending public Owner candidate**. On successful
claim, one transaction consumes the code and creates those records plus the
exact recoverable response. The UI reports `ACCOUNT_READY /
OWNER_SIGNER_PENDING`; the candidate is not an active Owner key, approval
signer, Root-history entry, or management authority. A public key upload,
password, account session, or legacy Control identity match cannot activate a
Root. A candidate becomes `ROOT_ACTIVE` only through the existing
`owner-bootstrap-v1` finite local-issuer protocol after the exact Owner key
both decapsulates the Hub challenge and signs its transcript. The pending
candidate is frozen to the claim; changing it requires a separately reviewed,
local-only pre-Root recovery path, never public reset or a new claim code.

After the authenticated bootstrap receipt, the normal page offers a separate,
visible **“Authorize this browser to manage Hub”** action. The normal UI names
the browser and Hub, scope, and expiry in user-facing terms; it hides raw IDs
and key fingerprints. A local Owner-key component reviews the exact typed
request and signs the existing canonical `OwnerDeviceGrant` with the Owner
private key. Reuse the existing `cicada.owner-device-enrollment.v1` public
manifest as implementation plumbing for this bridge; do not add an
account-cookie grant or new grant schema. A manifest file is an advanced
fallback, not a required manual copy/paste step:

```json
{
  "format": "cicada.owner-device-enrollment.v1",
  "hub_id": "<pinned Hub ID>",
  "owner_id": "<stable Owner ID>",
  "owner_key_id": "<active Owner signing key ID>",
  "device_id": "<same ACCOUNT_LOGIN device ID>",
  "device_key_fingerprint": "<full SHA-256 fingerprint>",
  "purpose": "CLIENT_CONTROL",
  "device_public_identity": { "id": "...", "kem_public": "...", "signing_public": "..." }
}
```

The browser imports that real grant and uses the existing Client enrollment
operation. It does not forge a signature or convert the account cookie into a
manager credential. The `ACCOUNT_LOGIN` record and Client device enrollment
are distinct records and guards even though they bind the same generated
browser public identity. Without this explicit grant/enrollment, the account
can use only account-scoped pages, not Hub topology management. Keep this
verification and grant step inside the second setup page's pending/ready
states; it is not a new account-registration form. The local component
integration is not yet implemented.

## Installer payload and authority

Use an OS CSPRNG to generate 32 random code bytes once at local install. Store
only a domain-separated digest of the code, bound to the claim ID, Hub,
origin, purpose and expiry. The installer prints the payload once; restart or
public HTTP calls never reveal or replace it. The QR is structured input for
the claim page, not a navigable URL. The payload includes:

```json
{
  "format": "cicada.hub-owner-claim.v1",
  "version": 1,
  "purpose": "INITIAL_OWNER_ACCOUNT_CLAIM",
  "origin": "https://hub.example.test",
  "hub_id": "<stable Hub ID>",
  "hub_fingerprint": "<64 lowercase hex over the complete Hub identity>",
  "account_id": "<stable account ID>",
  "owner_id": "<stable human Owner ID>",
  "claim_id": "<opaque random ID>",
  "code": "<32 random bytes, base64url without padding>",
  "issued_at": "<canonical UTC timestamp>",
  "expires_at": "<canonical UTC timestamp>"
}
```

The claim verifier is bound to `account_id` and `owner_id` as well as claim ID,
Hub, origin, purpose and expiry. The Hub fingerprint must be a separately
trusted SHA-256 over a canonical encoding of the complete Hub identity: Hub
ID, contract, key version, suite, and full Client-Control public identity. The
domain separator, canonical bytes, and public test vector remain to be frozen.
A short key ID, name, TLS hostname, or value returned only by the claim page is
insufficient. The payload's lifetime is finite (proposed default: one hour).
A local administrator can invalidate and
replace it only before claim completion; replacement invalidates the prior
code. There is no public issuer, status, or reset endpoint.

The installer uses Hub-only Store/setup code. It must not call `Control.New`
to create a compatibility human, Controller identity, workspace, local
Machine, or intent state. Account and Owner identities are stable Hub records
and distinct from all crypto key IDs. If local setup reserves account/Owner
IDs, the unclaimed claim record binds to them without treating them as an
active human or signer.

## Bootstrap HTTP operations

Use a separate `owner-account-claim-v1` setup/auth contract. Each HTTP body
and response carries the existing ML-KEM-768 / ML-DSA-65 / AES-256-GCM sealed
application framing, bound to a new account purpose and typed operation; claim code, password,
proofs, challenges, session material, and receipts are never plaintext JSON.
Reuse the existing Client-Wire cryptographic/framing implementation and Go
ML-KEM / ML-DSA operations, but do not use Client management sequence counters,
catalog operations, generic Client RPC, capabilities, or Guards for account
authorization. HTTPS, same-origin checks, and CSRF protections supplement the
application envelope. Freeze the exact packet type, purpose value, operation
bindings, canonical payload bytes, nonce rules, and response/retry packet
before implementation; this proposal does not define a new cipher suite or
wire schema. Do not alter frozen Client bindings or fabricate a Control Owner
ID. The existing `owner-bootstrap-v1` proof packet remains its own unchanged
contract.

| Operation | Purpose |
|---|---|
| `POST /v2/owner/account/claim/prepare` | Receives a bounded sealed request whose protected payload contains the installer payload, generated browser-device public identity, 32-byte client nonce, and 16-byte request ID. The new account-claim operation binding names the `INITIAL_OWNER_ACCOUNT_CLAIM` purpose. Before decryption, check only cheap outer size/route/purpose/claim-ID shape, visible claim lifecycle/expiry, rate limits, and concurrency. After authenticated open, check the code verifier and protected Hub/origin/purpose/expiry bindings. Completion must recheck eligibility and consume the code atomically. Return an authenticated, Hub-bound sealed challenge containing an opaque claim-session ID, exact Hub/account/Owner/origin and device-fingerprint bindings, 32-byte server nonce, and expiry no later than ten minutes or code expiry. It creates no credentials, key binding, Root, or normal session. Exact request retry returns the same protected response bytes; changed bytes conflict. |
| `POST /v2/owner/account/claim/complete` | Receives a bounded sealed request whose protected payload contains the exact claim/session/Hub/account/Owner/origin/device bindings, both nonces, request ID, username/password, strict public Owner candidate, and proof from the generated browser login-device key over the claim transcript. The body is at most 32 KiB. After bounded preflight and browser proof, atomically consumes the code and creates account credentials, stable account-to-human-Owner mapping, first `ACCOUNT_LOGIN` device, pending candidate, and cached protected response. It does not activate Root/history or issue login authority. Exact request retry returns the byte-identical protected response; changed bytes conflict. The envelope format and canonical transcript are to be frozen in the implementation contract, not invented here. |

The claim candidate is public, pending metadata only. Root activation reuses
`owner-bootstrap-v1`: its locally issued pairing binds the exact Hub,
account/Owner, full candidate fingerprint, purpose, operation, nonce and
expiry. The Owner must decapsulate its Hub-authenticated challenge with the
existing KEM private key and sign the exact domain-separated transcript with
the existing signing key. That protocol alone moves the pending candidate to
active Root/history. The browser separately proves its login-device identity
during claim. Public-key upload, password, code alone, or a Control key ID
cannot activate a Root.

No public response reveals whether a Hub is claimed, a username exists, or
which secret/proof check failed. Bound packet sizes, validate route/expiry/code
state and rate limits before expensive PQ work, and cap KEM/signature
concurrency. Claim sessions expire no later than the code and never become
cookies or Client capabilities. On lost claim success response, only the
byte-identical final request may retrieve the cached response while the same
account/device remain active; a changed request fails. Root bootstrap has
its own exact retry/recovery receipt. Root revocation disables receipt
recovery but never clears Root history.

## Account login, sessions and device revocation

Keep account authentication in a separate `owner-account-v1` contract. Its
typed routes use the existing ML-KEM-768 / ML-DSA-65 / AES-256-GCM sealed
application framing with a new purpose and operation binding; they do not use Client management sequence
counters, generic Client RPC, capability lists, or `Guard` authorization.
Authenticated HTTPS, same-origin checks, and CSRF remain defense in depth. A
successful account login only authorizes requests that also carry a valid
account-purpose envelope and fresh registered-device proof to
`/v2/owner/account/*`; the ordinary Client management path still requires the
exact Owner-signed `OwnerDeviceGrant`, `/v2/client/devices/enroll`, an
encrypted Client session, and existing operation Guards. An account cookie
may be issued only as an opaque, non-authoritative session locator; cookie
possession alone never authorizes even an account route, and the cookie is
never accepted by `/v2/client/rpc`, enrollment, or legacy routes. No
claim-session cookie exists.

| Operation | Request and checks | Response and replay rule |
|---|---|---|
| `POST /v2/owner/account/login/prepare` | A sealed request's protected payload binds `ACCOUNT_LOGIN`, Hub, canonical origin, username, registered device ID/key ID/full fingerprint, 32-byte client nonce, 16-byte request ID, and proof by that device key. Require same-origin HTTPS. | For a valid registered account/device proof, return a sealed Hub-authenticated challenge bound to `ACCOUNT_LOGIN`, random attempt ID, 32-byte server nonce, exact Hub/origin/account/Owner/device/key fingerprint, echoed client nonce, account/device epochs, and issue/expiry no more than 120 seconds apart. Other cases get one generic public rejection; do not fabricate a challenge when no registered device is authenticated or disclose whether a username exists. Exact request retry returns the same protected challenge bytes; same request ID with changed bytes conflicts. |
| `POST /v2/owner/account/login/complete` | A sealed request's protected payload binds `ACCOUNT_LOGIN`, request ID, all challenge fields/nonces/epochs/times, username, password, and a device signature over the challenge transcript. Require exact origin, unexpired unused attempt, current epochs, password-verifier success, and signature success. Verify the envelope and device proof before scheduling password KDF; perform at most one verifier operation per well-formed completion. Keep body logging disabled/redacted and cap body/KDF concurrency. | Return a sealed session response bound to `OWNER_ACCOUNT_SESSION`, Hub/account/Owner/device IDs, canonical origin, account/device epochs, issue/expiry, and a CSRF value for defense-in-depth. An optional opaque cookie is a locator only, never a bearer credential. Use `Cache-Control: no-store`; cookie, if used: `__Secure-cicada-owner-session`, `Secure; HttpOnly; SameSite=Strict; Path=/v2/owner/account`, no `Domain`, 30-minute idle and 12-hour absolute maximum. Exact request retry may return only the cached same response for the still-active session; it never creates another session. Changed bytes conflict. If unavailable after revocation/expiry, perform fresh prepare/complete. No password-only or unknown-device fallback. |
| `POST /v2/owner/account/logout` | A sealed request's protected payload binds `OWNER_ACCOUNT_LOGOUT`, Hub/account/Owner/actor-device/session IDs, both epochs, canonical origin, 32-byte fresh nonce, 16-byte request ID, and actor-device proof. Require matching `Origin`; cookie/CSRF are supplemental checks only. | Revoke only that account session and return a protected receipt; clear any locator cookie. Exact request retry returns the cached same result and does not revoke the device, Owner key, or Client enrollment. Changed bytes conflict. |
| `POST /v2/owner/account/devices/revoke` | A sealed request's protected payload binds `ACCOUNT_DEVICE_REVOKE`, Hub/account/Owner IDs, actor and target device IDs, account epoch, expected target device epoch, fresh nonce/request ID, issue/expiry (maximum 60 seconds), origin, and actor-device signature. Require a current session and active actor device. | Atomically increment target account-device epoch and revoke its account sessions. Return a protected `ACCOUNT_DEVICE_REVOKE` receipt with Hub/account/Owner/actor/target IDs, account epoch, prior/new target epochs, request ID and revocation time. Exact request ID+bytes returns the same receipt, including after self-revoke; changed bytes conflict and replay performs no other operation. Receipt is not a session. This revokes account login only; separately revoke matching Client enrollment through its existing Owner-authorized path if management access must also end. |

Every account-session request checks the sealed envelope's purpose, Hub,
canonical origin, account and device epochs, expiry, a fresh one-use request
nonce, and the account-route allowlist. A byte-identical retry may return only
the cached result for that same operation; a new operation needs a fresh nonce.
The registered device must sign each protected request; a cookie is only a
locator and never sufficient authority. CSRF and Origin checks supplement
these proofs. The account login's ML-DSA
challenge is its registered-device factor; it is independent of the password
verifier. The
`account_epoch` increments on password rotation/recovery or a global account
disable; a per-device `device_epoch` increments on that login-device's
revocation. The account UI may list only the current account's public device
metadata. Root signer revocation and Client device revocation remain separate
protocols. No new login-device enrollment route is defined here: unrecognized
devices stay blocked until a separate Owner-approved device-add flow exists. The
`account_epoch` and account `device_epoch` are not Client Wire
`session_epoch` or `device_key_version`; account fields never enter the
`OwnerDeviceGrant` schema or change Client sequence counters/capabilities.

Bound credential work explicitly: `username` is at most 128 UTF-8 bytes,
password at most 1,024 UTF-8 bytes (never truncated), a login request at most
8 KiB, and each completion performs at most one verifier operation. Permit at
most two password-KDF operations concurrently per Hub process and queue at
most four; reject excess work with a generic `429`/`Retry-After`. The verifier
algorithm and work factor are versioned server configuration, benchmarked for
the supported Hub, and capped to one accepted current profile plus any
explicitly retained migration profile; request fields cannot raise the cost.
The proposed 10-character minimum counts only when the registered device key
is locally held and cannot be obtained from the submitted account password
alone. Otherwise use the 15-character single-factor minimum.

## Password and durable state

NIST SP 800-63B-4 requires 15 characters for password-only remote
authentication. CICADA's requested 10-character minimum is appropriate only
if **every login** verifies both the password and an automatic PQC challenge
from a trusted registered device. The one-time setup code is not ongoing MFA.
There is no password-only fallback, including password reset or a new browser;
unknown devices require approval from an existing Owner.

Do not impose character-class rules or arbitrary rotation. Support
passphrases, password-manager autofill/paste, and at least 64 characters;
count the full password and reject over-limit inputs rather than truncate.
Block common, expected, compromised and service-context passwords on the
server, with actionable feedback. Keep UI strength feedback local and
bounded; do not claim precise entropy or use remote password-meter services.
Store only a salted verifier and scheme/work-factor metadata using a
NIST-aligned password hashing scheme. Benchmark work, rate-limit failures,
bound input size, and cap concurrent KDF work.

```text
UNCLAIMED + valid installer payload
  -> CLAIM_SESSION (short-lived; exact Hub + generated login device)
  -> ACCOUNT_READY / OWNER_SIGNER_PENDING (atomic account + verifier + stable
     Owner mapping + first login device + pending public candidate; no Root)
  -> ROOT_ACTIVE (only after owner-bootstrap-v1 possession proof)
  -> MANAGER_CLIENT_READY (only after explicit consent, exact OwnerDeviceGrant,
     and existing Client enrollment)

ACCOUNT_READY -> never UNCLAIMED; claim code cannot be reissued publicly
ROOT_REVOKED -> history remains; separate recovery design required
```

Code expiry, restart, password reset, Root revocation, and a zero active-Root
count must never reopen initial claim. Existing Root-active or Root-revoked
Hub volumes reject installer claims. A pre-Root account lockout or wrong
pending candidate can be repaired only through a separately reviewed,
local-only recovery that preserves account/Owner IDs and audit history; that
recovery is not implemented or fully specified here. Existing 0.0.5
`HUB_READY` human Owner IDs remain stable: use authenticated local migration
against the exact existing mapping, never create a replacement human or
rewrite IDs. The Hub account service depends on Store, Hub identity and its
account-route authority only; it does not require Control identity, intent,
workspace, or Controller Machine. Manager authorization must use the explicit
account-to-human-Owner binding plus an active Root and separately enrolled
Client grant, not `OwnerID == Control.Identity().ID`.

Every later account login requires password verification and a current PQC
signature challenge from an already registered, non-revoked login device. No
account session is issued until both succeed. Claim endpoints cannot enroll a
Client, approve a Client grant, bind a Node, create a Network membership, or
Join an Endpoint.

## Negative acceptance tests

- Wrong/missing/expired/consumed code, wrong origin or full Hub pin, wrong
  purpose, malformed/unknown fields, or Root history rejects before claim
  completion. Pin failure sends no code/password. No public issuer/status
  route or first-visitor claim exists.
- Public-only Owner key, wrong KEM recipient/ciphertext, KEM without signature,
  signature without KEM, altered transcript, replayed nonce, wrong
  Hub/account/device, expired challenge, or changed proof cannot activate a
  Root or enter active approval/history. Candidate upload alone remains
  visibly pending.
- Concurrent claims and restarts produce at most one account, verifier,
  pending candidate and first login device. Claim crash/retry tests distinguish
  pre-commit from post-commit; only an exact claim request recovers its cached
  response. Owner bootstrap exact proof retry recovers its own receipt.
- Losing the accepted one-time claim before Root activation never opens a
  public reset. Test the documented local-only pre-Root recovery boundary;
  active or revoked Root history is never reset.
- Password reset, expiry, restart, revocation and zero active Roots never
  reopen claim. Root-active/revoked volumes require local migration and retain
  exact IDs/grants/counters/history.
- Claim works with Control absent, a different Control identity, and no
  workspace/intent/Machine. Control key possession alone grants nothing.
- Every login requires password plus the registered-device PQC challenge;
  password-only, unknown or revoked device, claim cookie, expired attempt,
  stale epoch, cross-origin request, and Client RPC carrying only an account
  cookie do not issue an account session or Client capability.
- Account login completion, logout, and device revoke follow their exact
  one-shot/retry receipts and epoch checks. Account-cookie replay cannot call
  Client RPC; only the same browser identity's separately Owner-signed grant
  can enroll it. Altered grant fields and a fake/local-page signature fail.
- Test password lengths 9/10/14/15, common/context blocklist, passphrases,
  Unicode policy, no composition rules, no truncation, paste/password manager,
  generic errors, rate limits and bounded KDF concurrency.
- Scan URL/query/fragment/referrer, browser storage/cookies, process args/env,
  logs/traces/metrics/errors/diagnostics and Hub state for setup code,
  password, Owner private material, passphrases and proof nonces.
- Confirm the claim path uses the existing SPKI parser and cannot invoke
  general Client RPC or silently grant `CLIENT_CONTROL`, Node, Network, or
  Endpoint authority.

## Primary references

- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html),
  §3.1.1.2: 15 characters for single-factor passwords; at least eight may be
  used when a password is part of MFA. It also addresses blocklists, no
  composition rules, strength guidance, rate limits, and salted verification.
- [Official Headscale registration guide](https://headscale.net/stable/ref/registration/):
  create an owner before administrator-approved node registration; its
  optional pre-auth key is administrator-issued, one-use, and defaults to one
  hour. CICADA adopts neither its code nor its auth-key semantics.
