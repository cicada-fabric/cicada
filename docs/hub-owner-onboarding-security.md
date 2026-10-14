# Hub Owner claim security review

Status: design review only, 2026-10-14. No account-claim server route, password
verifier, installer claim code, account session, or account UI is implemented
by this note; in particular, no account-purpose sealed envelope or protected
account-session operation is implemented. The existing software 0.0.5
`owner-bootstrap-v1` remains a
separate, candidate-bound local issuance protocol; it is not public signup or
password login. See the [proposed account contract](hub-owner-account-contract.md),
[bootstrap contract](hub-owner-bootstrap-contract.md), and [panel guide](hub-web-panel.md).

## Design decision

Use an installer-generated, high-entropy, single-use claim secret as finite
initial authority. The installer prints it once alongside the Hub URL and a
complete Hub identity fingerprint. The claimant enters or scans the secret in
the claim page; it is a QR payload, not a URL and never a URL query or fragment.
The claim client obtains the Hub's public identity and verifies its complete
fingerprint against the independent installer payload before sending any claim
material. That fingerprint must cover a canonical, domain-separated encoding
of the Hub ID, contract, key version, suite, and complete Client-Control public
identity. A short key ID or a fingerprint derived from only one field is not
enough.

The code is a bearer authority: anyone who obtains it can race to claim the
account and first login device. Proof of possession proves control of submitted
Owner keys; it does not prove that those keys belong to the intended human.
Under the adopted trust boundary, the trusted physical administrator hands
the one-use code to the intended claimant. A codeholder who substitutes a
different public candidate can at most create an account and login device:
that candidate stays pending and cannot authorize Hub management until the
existing `owner-bootstrap-v1` local authority has verified real Owner
possession. This residual claim-squatting/lockout risk is why the code must be
transferred deliberately and why pre-Root recovery must be local-only.

The adopted boundary trusts the installed Hub build, its served panel, and the
physical administrator; a malicious host administrator is the deploying
user's responsibility. The Hub identity pin still verifies the protocol
identity and catches wrong-origin/identity mistakes, but it is not a separate
proof of JavaScript artifact integrity. An independently signed desktop UI,
enclave, or VM is not required by this design and is not a stop-ship condition.
Continue to keep account secrets out of unintended storage, URLs, and logs.

Keep the new claim protocol separate from `owner-bootstrap-v1`: that protocol
assumes a stable account and Owner ID already exist and a local operator has
issued authority bound to one exact candidate. A claim flow that creates the
account from a one-time installer code has a different authority source,
transaction, recovery state, and threat model. Claim, login, and protected
account operations must use the existing ML-KEM-768 / ML-DSA-65 /
AES-256-GCM sealed application framing with a new account purpose and typed
operation binding. Reuse the
existing Client-Wire cryptographic/framing code and ML-KEM / ML-DSA operations,
but do not use Client management counters, capabilities, or generic RPC for
account authority. HTTPS, Origin checks, and CSRF are additional defenses, not
the required Client-to-Hub application protection. The exact packet type,
purpose value, transcript/canonical encoding, nonces, and retry receipt remain
to be frozen in a separate implementation contract; this review does not
invent a new cipher or wire format. Do not add a public issuer or claim-status
endpoint.

## Required invariants

- **Installer pin and accepted software boundary.** The displayed/scanned
  origin and full Hub identity fingerprint come from installer output, not
  only from the page being visited. Reject a mismatch before transmitting the
  secret, password, or candidate identity. Use authenticated HTTPS for remote
  claims. The adopted threat model trusts the installed Hub build and its
  served UI; it does not require a separately signed desktop artifact.
- **One durable claim authority.** Generate the code with the OS CSPRNG, with
  256 random bits as specified by the account contract. Store only a verifier,
  the bound Hub, purpose (`INITIAL_OWNER_ACCOUNT_CLAIM`), expiry, and lifecycle state.
  Do not print it
  again after the install ceremony. A local operator may revoke/reissue it
  only while no claim has committed; a public endpoint may not issue, reset,
  or reveal it.
- **One account claimant; Root activation is separate.** Persist claim state
  across restart. In one transaction, consume the code, create the stable
  account/Owner mapping, first `ACCOUNT_LOGIN` device, pending public candidate,
  and accepted-response receipt. At this point no Owner key is active, no Root
  history exists, and no management authority is granted. A separate existing
  finite `owner-bootstrap-v1` pairing must verify the exact candidate's KEM
  and signature proof before a transaction activates the Root and history.
  Concurrent claims yield at most one account; exact claim retries recover
  only the same response. A lost account claim cannot be publicly reset.
- **Pending candidate is not authority.** Candidate upload is public metadata
  for the exact stable Owner/account mapping. It cannot appear in the active
  key set, approval signer list, Root history, or any management Guard. The
  existing finite bootstrap operation proves KEM decapsulation and ML-DSA
  signature over the exact Hub/account/Owner/purpose/fingerprint/nonce/expiry
  transcript. Only that proof moves the candidate to `ROOT_ACTIVE`.
- **Root history never resets.** Once the first Root commits, token expiry,
  account-password reset, signer revocation, empty active-key count, or restart
  cannot restore initial-claim eligibility. Recovery and new trust epochs need
  a separate explicit protocol.
- **Control is not the account authority.** Store the human account and
  account-to-Owner binding independently from Control's cryptographic
  identity, intent service, and manager workspace. A `Control.Identity()` ID
  match is not a new user grant. Owner account authentication, Root signer
  authority, Client manager capabilities, Node enrollment, Network membership,
  and Endpoint Join remain separate states and guards. Preserve existing
  software 0.0.5 `HUB_READY` human Owner IDs exactly; authenticated local
  migration may add account metadata but must not mint replacement IDs.
- **Private keys stay local.** Accept only the complete supported public
  identity and bounded proof packets. Reject unknown/private fields. Never ask
  for a private key, seed, PEM, or key passphrase in the browser or send one to
  Hub storage. After Root activation, the user may visibly authorize the same
  browser public identity for management. A local Owner-key component must sign
  the existing exact `OwnerDeviceGrant`; the browser cannot fake that
  signature, and its account cookie is not a Client credential. The browser
  still needs existing Client enrollment and Guards; Node INITIAL is separate.
- **Credentials stay out of incidental channels.** Send the setup secret,
  password, challenges, proofs, and account-session data only inside the
  post-quantum sealed application envelope. Never place them in a URL,
  browser history, referrer, command arguments, environment, analytics,
  application logs, traces, debug output, local/session storage, or IndexedDB.
  HTTPS is supplemental transport protection, not a substitute for that
  envelope. Keep request-body logging disabled/redacted and avoid echoing
  secrets in errors. A cookie, if present, is an opaque non-authoritative
  session locator; each protected account request also requires a sealed
  account-purpose packet, fresh nonce, current epochs, and registered-device
  signature. Clear claim form values after completion or cancellation.

## Password policy and bounded work

The proposed account login, logout, and login-device revoke fields, epochs,
post-quantum envelope requirement, CSRF checks, and replay semantics are in the
separate [account contract](hub-owner-account-contract.md). These are not
current routes. Account-session authority is limited to account endpoints and
cannot be translated into Client Wire counters or capabilities. A cookie by
itself authorizes no account or Client operation.

NIST SP 800-63B-4 requires at least 15 characters for a centrally verified
password used as a single factor. It permits an eight-character minimum only
when the password is actually part of a multi-factor process. The install code
is only for initial claim and is not a factor for later logins. Therefore a
username/password-only Owner login should use at least 15 characters. The
proposed 10-character floor is conditional on every login also requiring an
automatic signature challenge from a trusted registered PQ device. That makes
the device key a real second factor only when it is locally held and cannot be
obtained from the submitted account password alone; otherwise use the
15-character single-factor minimum. Ten characters is above NIST's
8-character MFA minimum, not its single-factor minimum. The install code is
never reused as an ongoing factor.

Do not impose upper/lower/digit/symbol class rules. Permit passphrases,
password managers, paste, and at least 64 characters; count the full submitted
password without silent truncation. Reject common, expected, and compromised
passwords server-side and explain the rejection. Include context-specific
whole-password candidates such as the service name and username; do not reject
arbitrary passwords just because they contain a username substring. Offer
local, actionable strength feedback based on length and common-pattern checks,
not a misleading precise entropy number. Do not send the candidate to a remote
strength service or breach-query service.

Bound input size explicitly and reject over-limit values rather than truncate.
Use a current NIST-aligned salted password-verification scheme, benchmark its
cost on supported Hub hardware, and cap concurrent verification work. Rate
limit failed claims and logins before expensive cryptographic work. Password
storage must contain a salted verifier and algorithm/work-factor metadata, not
the password or a fast unsalted hash. Use generic public failures for unknown,
expired, consumed, or invalid claim codes and avoid a status endpoint that
leaks whether a Hub has already been claimed.

Keep verifier work and proof work behind cheap packet-size, route, code-state,
expiry, and rate-limit checks. Reuse the existing Go cryptographic
implementation and fixed wire framing; do not add an online password meter or
breach-lookup service. A compact maintained local blocklist and linear-time
length/pattern feedback are enough for the first version; cap accepted input
length and cryptographic concurrency so public requests cannot trigger
unbounded CPU or memory work. QR rendering may encode the same structured
payload as manual copy/paste; it must not turn the secret into a navigable
URL.

## Headscale comparison

Headscale's official web-registration workflow requires an existing user and
an administrator approval of the node's registration. Its alternative
pre-authenticated key is created by the administrator, defaults to one use
and a one-hour lifetime, and is intended for non-interactive node enrollment.
The useful precedent is explicit owner creation plus a finite enrollment
authority; neither workflow equates an arbitrary first visitor with the owner.
Do not add a Headscale/Tailscale dependency or reuse its auth-key semantics for
CICADA Root authority.

## Negative acceptance tests for the next checkpoint

1. Wrong/missing/expired/consumed code, wrong origin, wrong complete Hub
   fingerprint, changed Hub key/version/suite, and public-key-only submissions
   cannot create an account or reveal claim state. A pin mismatch sends no code,
   password, or candidate to the server. Correct HTTPS but a missing, malformed,
   wrong-purpose, replayed, or invalid sealed application envelope is rejected;
   the code/password never appear in plaintext HTTP payloads, logs, or errors.
   UI artifact signature is outside this
   acceptance contract because the adopted boundary trusts the installed Hub
   build and served panel.
2. A valid code with a changed account, key, purpose, Hub, operation, nonce,
   expiry, ciphertext, invalid ML-DSA signature, or invalid ML-KEM possession
   cannot activate a Root. A valid signature without KEM possession and a valid
   KEM response without signature both fail.
3. Two concurrent first-claim attempts with the same code but different
   accounts/keys yield exactly one committed account, one first login device,
   and one pending candidate. Claim alone creates no active Root/history.
   Separately test that only exact Owner possession proof activates Root, then
   that only a separate real OwnerDeviceGrant plus Client enrollment grants
   management. Test crashes before/after each commit, restart, and lost claim
   response.
4. Restart, code replay, account-password reset, Root revocation, and zero
   active Root keys never reopen claim. Local reissue before any commit
   invalidates the old code; public callers cannot trigger reissue.
5. A Control identity mismatch, unavailable Control intent service, or absent
   manager workspace does not block independent account claim; Control key
   possession alone never creates or authenticates the human Owner account.
6. Assert no password, setup code, proof nonce, private field, or account
   cookie value appears in URLs, query/fragment, referrer, logs, traces, error
   text, JS storage, installer diagnostics, or Hub logs. If a cookie is used,
   it is only a non-authoritative locator, Secure/HttpOnly/SameSite and scoped
   to account routes; test that cookie-only calls fail. Check code/password
   are sent only after the independent full-fingerprint comparison and only
   inside the sealed application envelope over authenticated HTTPS.
7. Password cases cover lengths 9/10/14/15, passphrases, common and
   service-context passwords, Unicode counting/normalization if supported,
   no composition-class rule, no truncation, and manager/paste behavior. Verify
   server-side blocklist, generic login errors, rate limits, and bounded KDF
   concurrency under parallel invalid requests.
8. After account claim, verify that pending public Owner data, account password,
   and account cookie cannot activate Root or call Client RPC. Only the existing
   Owner bootstrap proof activates Root. Then verify that the same browser
   identity receives management authority only after visible consent, a real
   Owner signature over the existing `OwnerDeviceGrant`, normal Client
   enrollment, and server Guard checks. Node INITIAL remains separate.

## Sources checked 2026-10-14

- [NIST SP 800-63B-4, Authentication and Lifecycle Management](https://pages.nist.gov/800-63-4/sp800-63b.html), especially §3.1.1.2 and Appendix A. This is the current revision, superseding SP 800-63B-3.
- [Official Headscale registration methods](https://headscale.net/stable/ref/registration/)
- [Official Headscale getting started guide](https://headscale.net/stable/usage/getting-started/)
