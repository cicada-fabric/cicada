# Hub Owner account protocol

Status: the six-operation `owner-account-v1` wire contract is frozen in
[`internal/hubaccountwire`](../cicada-go/internal/hubaccountwire), and current
dirty source includes its Store/schema-61, Hub account service, HTTP composition,
password policy, CLI claim issuer, and two-page browser/WASM flow. Focused wire,
crypto, migration/restore, real TCP protocol, CLI, selected race, and targeted
vet checks pass. The bounded 18-step disposable Chromium account gate and
standard Client-over-TCP Docker interop gate also pass; see the
[captured validation record](hub-owner-account-validation.md). These scoped
results do not establish release readiness or production deployment.

This protocol is separate from the already-existing `owner-bootstrap-v1` finite
Root signer enrollment. It does not change Client Wire v1, Client contract
v1.6.5, catalog 55, Client counters, grants, or Android. The adopted trust
boundary treats the installed Hub build and physical administrator as trusted;
a malicious host administrator is the deployment owner's responsibility.

## Resulting authority

The installer gives the intended claimant a one-use claim card together with the
Hub URL. The card binds a 256-bit code to the exact Hub, origin, stable account
and Owner IDs, purpose, and finite expiry. The browser verifies the page origin
and the complete Hub identity fingerprint before sending anything. The code,
password, challenges, proofs, session token, and receipts travel only in the
existing ML-KEM-768 / ML-DSA-65 / AES-256-GCM application envelope. HTTPS and
same-origin checks are additional defenses.

A successful claim atomically creates account credentials, the first
`ACCOUNT_LOGIN` device, and a **pending public Owner candidate**. It does not
create an active Root, Root history, approval signer, Client grant, or Manager
session. Root activation requires the separate existing `owner-bootstrap-v1`
flow: an exact local finite issuance, Hub challenge decapsulation by the Owner
KEM key, and a valid transcript signature by the Owner signing key. Management
then still needs a real Owner-signed `OwnerDeviceGrant`, ordinary Client
registration, and the existing server Guard. Account login never substitutes
for those checks.

The account password is at least 10 Unicode code points and at most 1,024 UTF-8
bytes; the server rejects a small maintained common/context password blocklist
and applies no character-class rules. The current verifier is versioned
`PBKDF2-SHA256-600000-v1`, with a per-record 32-byte salt and verifier. The
password is never truncated. The registered device is also proven on every
login; the installer code is not an ongoing factor.

## Installer claim card and Hub pin

The public card has exactly these fields; unknown fields, duplicate JSON keys,
noncanonical encodings, and oversized card bytes are rejected by
`DecodeClaimCard` before the UI presents or transmits the code.

```json
{
  "format": "cicada.hub-owner-claim.v1",
  "version": 1,
  "purpose": "INITIAL_OWNER_ACCOUNT_CLAIM",
  "origin": "https://hub.example",
  "allow_loopback_http": false,
  "hub_id": "<stable Hub ID>",
  "hub_fingerprint": "<64 lowercase hex SHA-256>",
  "account_id": "<stable account ID>",
  "owner_id": "<stable human Owner ID>",
  "claim_id": "<16 random bytes as lowercase hex>",
  "code": "<32 random bytes as unpadded base64url>",
  "issued_at": "<canonical UTC RFC3339Nano>",
  "expires_at": "<canonical UTC RFC3339Nano>"
}
```

The fingerprint is SHA-256 over the domain separator
`cicada/owner-account/hub-identity/v1\0` followed by canonical JSON for the
complete existing Hub identity (`contract`, `hub_id`, full
`control_public_identity`, `control_key_version`, `suite`). A name, URL, key ID,
or a value supplied only by the web page is not a substitute. The default card
lifetime is one hour. Code issuance and replacement are local installer/admin
operations only; there is no public issuer, status, or reset endpoint. Once
claim completion commits, no public operation reopens the claim. A pre-Root
local recovery procedure remains a separate reviewed operation and must retain
the stable account/Owner IDs and audit history.

A visibly marked synthetic vector and verifier live at
[`internal/hubaccountwire/testdata`](../cicada-go/internal/hubaccountwire/testdata).
Its all-zero claim code is test-only and must never be used in a deployment.

## Frozen packet and route bindings

The account packet is a strict canonical JSON object containing
`format: cicada.owner-account-packet.v1`, `version: 1`, the sender's complete
public identity, and the existing Client Wire packet (`route` plus encrypted
`envelope`). The outer public identity is a candidate only on initial
`claim.prepare`; the account service's persisted state and protected one-use
code authorize the claim. The packet parser rejects unknown/duplicate fields,
malformed identities, invalid routes, and noncanonical JSON.

| Operation | HTTP route | Operation binding | Purpose |
|---|---|---|---|
| Claim prepare | `POST /v2/owner/account/claim/prepare` | `owner.account.claim.prepare` | `INITIAL_OWNER_ACCOUNT_CLAIM` |
| Claim complete | `POST /v2/owner/account/claim/complete` | `owner.account.claim.complete` | `INITIAL_OWNER_ACCOUNT_CLAIM` |
| Login prepare | `POST /v2/owner/account/login/prepare` | `owner.account.login.prepare` | `ACCOUNT_LOGIN` |
| Login complete | `POST /v2/owner/account/login/complete` | `owner.account.login.complete` | `ACCOUNT_LOGIN` |
| Session inspect | `POST /v2/owner/account/session/inspect` | `owner.account.session.inspect` | `OWNER_ACCOUNT_SESSION` |
| Session logout | `POST /v2/owner/account/session/logout` | `owner.account.session.logout` | `OWNER_ACCOUNT_SESSION` |

Each request uses a fresh random 16-byte lowercase-hex operation ID and 32-byte
client nonce. Each fixed account packet uses sequence 1. Claim and login
handshakes use Client Wire session epoch 1; authenticated account-session routes
use the protected current `account_epoch`. Protected bodies also carry current
`account_epoch` and `device_epoch`, canonical origin, device key ID and full
fingerprint. These account epochs are not Client Wire `session_epoch` or
`device_key_version`.

The strict body limits are 384 KiB for the outer request/response packet,
256 KiB for the nested Client Wire packet, 32 KiB for claim completion, and 8
KiB for every other protected account body. The claim challenge expires within
10 minutes and no later than the card expiry; a login challenge expires within
2 minutes; an account session expires within 15 minutes; a single protected
session request is valid for at most 60 seconds. Request and challenge nonces
are 32 bytes. Account-device IDs are exactly `accountdev_` plus 16 random bytes
as lowercase hex.

The Go API owns route IDs, sequence, operation, purpose, nonces, and typed
payloads. Browser code must not construct these fields directly. The main
entrypoints are `NewClaimPrepare`, `NewClaimCompleteFromChallenge`,
`NewLoginPrepare`, `NewLoginComplete`, `NewSessionInspectRequest`,
`NewLogoutRequest`, `SealClientRequest`, and `OpenClientResponse`. Server-side
helpers are `PreflightRequest`, `OpenRequestAt`, `RequestRoute`, and
`SealResponse`. `OpenClientResponse` checks the independently pinned full Hub
identity, exact route echo, response type and format, and echoed operation,
Hub, Owner, and device IDs.

### Claim

`ClaimPrepare` contains the full card, generated account-device ID and
fingerprint, request ID, client nonce, and issue time. `ClaimChallenge` returns
the exact origin/Hub/account/Owner/claim/device bindings, attempt ID, echoed
prepare request and client nonce, server nonce, account/device epochs, and
expiry. A reload can continue from the persisted exact encrypted prepare
request/response; `NewClaimCompleteFromChallenge` does not need the card or
plaintext code again.

`ClaimComplete` echoes the authenticated challenge bindings and both nonces and
contains username, password, the strict public Owner candidate, and a fresh
request ID/client nonce. The Client Wire envelope proves possession of the
browser device signing key. Successful challenge decryption and exact nonce
return proves possession of its KEM key. The service checks the code only after
opening the protected prepare body, then rechecks claim eligibility in the
transaction that consumes it. The completion transaction writes credentials,
stable account-to-Owner mapping, first login device, pending public candidate,
and the exact protected receipt together. The receipt says
`ACCOUNT_READY_OWNER_SIGNER_PENDING`, `PENDING_PROOF`, and
`root_active:false`.

The Owner candidate must be distinct from both the Hub Client-Control identity
and the generated account-login device identity.

### Login and account session

`LoginPrepare` binds username, canonical origin, account/Owner/device and public
key fingerprint, request ID, and client nonce. A registered device receives a
Hub-authenticated sealed `LoginChallenge` with an attempt ID, server nonce,
epochs and expiry. There is no fabricated challenge for unknown or unregistered
devices. `LoginComplete` echoes the complete authenticated challenge scope and
nonces and carries the password under the envelope. The response is a sealed
`SessionReceipt` with a random 32-byte account session token, device/account
epochs, and issue/expiry times.

The session token remains inside the encrypted receipt and in the Go-WASM
opaque session-handle map; browser JavaScript must not persist, log, or expose
the token. It is never a Client or Manager credential. There is no cookie
authority. Session inspect returns the current username, active login-device
metadata, and pending/active/unavailable Root status with candidate key ID and
fingerprint. Session logout revokes only that account session.

The browser login-device private identity is stored only as AES-256-GCM
ciphertext in IndexedDB, bound to the Hub/origin/account/device/public identity
with a non-extractable random WebCrypto wrapping key. The account password does
not derive or unlock that key. This protects the saved identity within the
browser profile; it is not hardware-backed protection. Exact sealed protocol
packets needed for retry may also be persisted, but plaintext claim codes,
passwords, private identity bytes, and session tokens may not be.

Only the six operations in the table are in this bounded protocol. Device
revocation, password reset, unknown-device enrollment, generic account RPC,
account cookies, and management authorization are not implemented by this
contract. An unknown device remains blocked until a separately approved
account-device-add flow exists.

## Preflight, errors, retries, and storage

Before post-quantum decapsulation, the service checks only bounded outer size,
route, operation, claim ID shape, stored lifecycle/expiry, rate limit, and
concurrency. It checks the protected code and inner Hub/account/Owner/origin
bindings only after authenticated open, then rechecks authority and epochs in
the transaction. The protected packet proves the sender's signing key; the
challenge return proves possession of the sender's KEM key. The full public
identity alone is not authority.

Exact retries return the original cached protected response bytes for the same
operation ID and byte-identical packet. Changed packet bytes under an existing
operation ID conflict, and a client nonce cannot be reused for another accepted
operation by the same account device, including across newly opened sessions.
An exact packet retry keeps its original operation ID and nonce. A rejected
wrong-password completion leaves its challenge available; a corrected attempt
uses a fresh request ID and client nonce against that same server challenge.

Claim completion and accepted login receipts are durable across restart. An
exact consumed login-completion packet can recover its original receipt after a
later login revokes that session, while the receipt's session token remains
revoked. An exact logout retry can recover its committed receipt after session
revocation only after current device proof and account/device epoch checks; that
recovery does not authorize any new operation. Session requests use a bounded
128-operation replay ledger per session. Root bootstrap has its separate exact
proof/receipt retry. Revocation disables bootstrap receipt recovery but never
clears Root history.

The 60-second request freshness check applies to new packets. For an exact
previously accepted login-completion or logout packet, the Hub first matches
the packet digest to its durable receipt under the current account, device and
credential epochs, then authenticates the original device envelope. Only the
age check is skipped so the exact response can be recovered after delay or
restart; malformed or altered bytes, a new operation ID/nonce, revoked devices,
and stale epochs do not qualify. Session request structure and its maximum
issued-to-expiry interval remain validated.

If a prepared claim challenge expires before completion, the local operator
must explicitly cancel and issue a replacement claim card. A replacement is
never issued implicitly by the public claim route.

The HTTP handler accepts only `POST`, bounds the body, and returns raw sealed
packet bytes. Public errors do not reveal which identity, credential, proof, or
claim-state check failed. Current handler classes are `403` generic reject,
`405` wrong method, `413` over-size, `503` unavailable, and `429` busy/rate
limited with `Retry-After: 1`. If an `Origin` header is present it must match
the configured exact origin; the protected body is independently bound to that
origin. Browser same-origin policy, HTTPS, and CSRF protections supplement the
application envelope.

Password verifier work is bounded and rate-limited; the current implementation
admits at most two concurrent cryptographic workers and rejects excess work
with a generic busy response. No password, code, session token, private key,
passphrase, or decrypted body may appear in URLs, logs, errors, traces, metrics,
or HTTP plaintext. Use `Cache-Control: no-store` for account pages and packets.

## Public-key file parsing and private material

Public OpenSSL keys are accepted only as one PEM `PUBLIC KEY` SubjectPublicKeyInfo
with absent algorithm parameters and exact ML-KEM-768 / ML-DSA-65 OIDs and key
sizes. The shared parser API is `publicidentity.ParseOpenSSLSPKIPublic` or
`ParseOpenSSLIdentity`; it is the same parser used by the local Owner CLI. No
private PEM parser is part of this API. Private Owner PEMs, seeds and
passphrases stay with the local key component and never enter the Hub or browser
claim form.

## Required negative coverage before release

- Wrong, expired, consumed, or changed claim code; wrong origin or complete Hub
  pin; wrong purpose; duplicate/unknown/noncanonical JSON; changed account,
  Owner, Hub key, route, epoch, nonce, or operation ID.
- Public-key-only claim, malformed ciphertext, invalid device signature,
  invalid KEM challenge response, altered challenge, wrong device identity,
  expired challenge, or changed completion after a committed retry.
- Concurrent claim races, Hub restart, durable exact retry after lost response,
  and no claim reset after claim commit, Root activation, Root revocation, or
  account/password reset.
- Login for unknown/unregistered/revoked device, wrong password, bad proof,
  stale epoch, expired attempt, replayed nonce, cookie-only request, cross-origin
  request, or account token presented to Client RPC.
- Session-inspection Root state truthfully distinguishes pending candidate,
  active Root, and unavailable/revoked candidate; claim receipt never reports
  Root active.
- Ensure the same browser public identity receives management authority only
  after visible consent, a genuine Owner signature over the existing
  `OwnerDeviceGrant`, normal Client enrollment, and server Guard checks.
- Verify no clear secret values in HTTP payloads/logs or unintended browser
  storage, and verify key parsing rejects malformed PEM, wrong OID, present
  parameters, wrong size, and trailing blocks/data.

## References

- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html),
  especially password blocklists, rate limits, no composition rules, and
  salted verifier guidance. The 10-character floor is conditional on every
  login also proving the registered PQ device; it is not password-only MFA.
- [Official Headscale registration guide](https://headscale.net/stable/ref/registration/):
  an administrator creates the user and explicitly approves device
  registration. CICADA does not use a generic first-visitor-as-owner flow or
  inherit Headscale auth-key semantics.
