# Hub Owner account security baseline

Status: security contract for `owner-account-v1`, updated 2026-10-14. The
account wire primitives, strict claim-card decoder, shared OpenSSL SPKI public
parser, Store/service, HTTP composition, and browser/WASM integration are
implemented in the captured dirty source. The bounded 18-step disposable
Chromium account gate and standard Client-over-TCP Docker interop gate pass;
see the [validation record](hub-owner-account-validation.md). These scoped
results are not a release-validation receipt. See the
[frozen account contract](hub-owner-account-contract.md), separate
[Root bootstrap contract](hub-owner-bootstrap-contract.md), and
[panel guide](hub-web-panel.md).

## Adopted trust boundary and authority

The installed Hub build, its served panel, and the physical administrator are
trusted. A malicious host administrator is the deploying user's
responsibility. A separately signed desktop UI, enclave, or VM is not required
by this design and is not a stop-ship condition. The Hub identity fingerprint
still binds the protocol to the independently supplied Hub identity; it is not
an artifact-integrity signature.

The install code is a bearer authority. Anyone who gets the 256-bit code can
race to complete initial account claim. The physical administrator transfers
it deliberately to the intended claimant. The code is one-use, expires after
one hour, and is not reprinted or publicly reset. A claimant who substitutes a
different public Owner identity can at most create the stable account, first
login device, and a **pending public Owner candidate**. The candidate is not an
active Root, history row, approval signer, or Manager identity. A separate
existing `owner-bootstrap-v1` finite local issuance must prove KEM challenge
decapsulation and transcript signature for that exact candidate before Root
activation. Management still needs a separately signed `OwnerDeviceGrant`,
normal Client enrollment, and existing operation Guards.

## Required invariants

- **Independent pin before send.** Verify the exact page origin and the
  domain-separated SHA-256 of the complete Hub identity against the installer
  claim card before sending the code, password, or candidate identity. Reject
  mismatch locally. The fingerprint includes contract, Hub ID, full public
  identity, key version, and suite. The claim card is structured text/QR input,
  never a navigable URL or query string.
- **Application protection.** Claim code, password, challenges, proofs,
  session token, and receipt stay inside ML-KEM-768 / ML-DSA-65 / AES-256-GCM
  application envelopes. HTTPS, Origin checks, and CSRF are defense layers,
  not substitutes for the envelope. Account packets use new typed purpose and
  operation bindings; they do not consume Client management counters or create
  Client capabilities.
- **One durable claim.** Generate code with the OS CSPRNG; persist only a
  bound verifier and lifecycle state. Claim completion atomically creates
  credentials, stable account-to-Owner mapping, first `ACCOUNT_LOGIN` device,
  pending candidate, and exact protected receipt. Concurrent attempts produce
  at most one accepted claim. Exact packet retry returns only the original
  cached response; changed bytes conflict. Restart, expiry, password reset,
  Root revocation, and zero active Roots never reopen public claim.
- **Separate Root activation.** Public key upload, installer code, password,
  account session, or Control identity match cannot activate Root. The existing
  finite bootstrap proof must verify both Owner KEM and signing-key possession
  against the exact candidate. Root history remains durable after revocation.
- **Separate session authority.** Login requires the password and the
  registered device's PQ challenge/proof every time. The protected session
  token lives in the encrypted receipt and an opaque Go-WASM handle; it is not
  a cookie or bearer credential and is never Client authorization. Only the
  six defined account operations are available: claim prepare/complete, login
  prepare/complete, session inspect, and session logout. Unknown device
  enrollment, account password reset, device revoke, generic account RPC, and
  manager operations are not part of this checkpoint.
- **Private keys stay local.** The browser receives only complete public
  identities. OpenSSL public SPKI parsing is shared with the local Owner CLI
  and rejects wrong OID, parameters, size, extra blocks, and unknown fields.
  Private PEMs, seeds, and passphrases never enter the browser claim UI or Hub
  state. The browser's login-device private identity is kept as AES-GCM
  ciphertext in IndexedDB, bound to the Hub/origin/account/device/public key
  and wrapped by a non-extractable random WebCrypto key. The account password
  does not derive or unlock that key. This is browser-profile protection, not
  hardware-backed protection.
- **Bound CPU and input.** Reject oversized/noncanonical JSON, invalid route,
  purpose, claim ID shape, state, expiry, and rate/concurrency overflow before
  expensive PQ work. Check protected code and account bindings only after the
  authenticated envelope opens, then recheck state transactionally. Password
  input is at most 1,024 UTF-8 bytes and is never truncated. The current
  verifier is versioned `PBKDF2-SHA256-600000-v1`; current code admits at most
  two concurrent verifier workers. Final deployment benchmarking and full
  integration validation remain pending.
- **No incidental secret channels.** Do not put plaintext code, password,
  session token, private identity bytes, or passphrase in URL, query, fragment,
  history, referrer, logs, errors, traces, metrics, process arguments,
  environment, diagnostics, or browser storage. IndexedDB may hold only the
  locally encrypted device identity and exact sealed protocol packets needed
  for retry. HTTP account bodies contain only the sealed packet. Return generic
  public authentication errors.

## Password policy

The implemented policy requires at least 10 Unicode code points and at most
1,024 UTF-8 bytes, blocks a small versioned set of common and service-context
passwords, and imposes no composition classes. It is acceptable only while
every login also proves possession of a locally held registered PQ device; the
install code is never a login factor. If a future mode permits password-only
login, it needs a separately reviewed minimum of at least 15 characters.

NIST SP 800-63B-4 discourages composition rules, calls for blocklists and
rate-limiting, and requires a salted password verifier resistant to offline
guessing. Keep local strength feedback bounded and actionable; do not claim a
precise entropy score or send passwords to remote meters or breach-query
services. Benchmark KDF latency and concurrency on supported Hub hardware
before release.

## Negative acceptance coverage

The final integration gate must show that wrong/expired/consumed codes, wrong
origin or full Hub pin, changed key/route/purpose/nonce/epoch, malformed or
ambiguous JSON, and public-key-only submissions cannot claim an account. A
pin mismatch must transmit no claim code, password, or candidate. Exercise
concurrent claim races, restart, exact lost-response retry, and changed-packet
conflict; verify the receipt remains pending and no active Root/history is
created.

Login tests must cover unknown/unregistered devices, wrong password, bad PQ
proof, expired challenge, stale epoch, replayed nonce, and generic failure
responses. Cookie-only calls and account-session packets sent to Client RPC
must fail. A current Root is shown as active only for the exact active
candidate; pending or revoked/unavailable candidates must not be mislabeled.
Logout must revoke only the account session.

Scan HTTP payloads, logs, error text, URL/referrer, browser storage, and
installer diagnostics for the claim code, password, session token, private
material, or passphrase. Test the SPKI parser against malformed PEM, unknown
algorithm, present parameters, wrong key size, duplicate/trailing blocks, and
private-key labels. The published claim-card vector and all other public
cryptographic fixtures must remain explicitly synthetic and must never
initialize a deployment.

## References

- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html),
  password blocklist, rate-limit, composition, verifier, and MFA guidance.
- [Official Headscale registration guide](https://headscale.net/stable/ref/registration/):
  administrators create users and explicitly approve device registration.
  CICADA does not equate the first web visitor with an Owner or reuse
  Headscale auth-key semantics for Root authority.
