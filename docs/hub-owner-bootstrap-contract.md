# Hub first Owner signer bootstrap contract

Status: bounded `owner-bootstrap-v1` protocol contract for the 2026-10-13
checkpoint. Source and validation status are tracked separately in
[the validation record](hub-owner-bootstrap-validation.md). This contract does
not change the frozen Android Client contract, encrypted Client wire version,
or operation catalog.

## Scope

This protocol lets a locally controlled, already initialized Hub install its
first external Owner approval signer. It establishes one stable Hub account
and its human Owner mapping before any Owner key is accepted. The Owner private
identity is generated or imported on the operator's machine and remains there.
The Hub receives only the public identity after proof of possession.

The bounded checkpoint covers local Hub setup, one finite first-signer
authority, proof and receipt recovery, and reuse of the existing Owner-signed
Client enrollment and Node INITIAL enrollment paths. It does not implement the
full onboarding product: there is no account login, password/SSO recovery,
public signup, Hub web setup panel, unified QR pairing UI, Android bootstrap
client, Windows private-key custody, or general device enrollment protocol.
The Android repository remains unchanged and does not support this bootstrap
flow. Node INITIAL continues to use its existing enrollment path after a
Client with the existing OwnerDeviceGrant is available.

The Owner signer's local profile is a Unix directory with mode 0700 containing
`owner-signer.json` with mode 0600. It stores the private identity as ordinary
local file data; this checkpoint does not encrypt that file at rest or use an
HSM/OS key vault. Protection depends on local filesystem permissions and
machine custody. Client-to-Control management RPC remains decrypted at Control;
this first-Root mechanism does not change that boundary or peer Endpoint E2EE.

The new HTTP application operation is separate `owner-bootstrap-v1`; it reuses
Client wire 1 packet framing and the Hub's existing Client-Control public
identity. It adds no entry to the frozen Client operation catalog. At this
checkpoint the surrounding identifiers remain Client contract v1.6.5, wire
1, catalog 55, and software 0.0.5. This source candidate does not imply Docker,
Android, Native, physical-device, or public-HTTPS acceptance; see its separate
[validation record](hub-owner-bootstrap-validation.md).

## Authority and account state

`cicada hub setup` is a local deployment-channel operation. It atomically
creates a stable account ID, a human Owner Principal ID, display label, Hub
origin, and `HUB_READY` setup record. The account ID and Owner ID are distinct
from every Hub cryptographic key ID. This command accepts no device upload or
Owner private key. There is no public setup, issuer, signup, or bootstrap
status endpoint. Setup records the operator-supplied origin but cannot verify
that public DNS, TLS termination, or the deployed listener actually serves at
that origin; the operator must verify deployment routing independently.

An existing deployment can retain its existing exact self-owned active human
as a `LEGACY_COMPAT` manager without changing Owner IDs or rewriting grants.
That compatibility state preserves its already authorized behavior but does
not claim a new configured Hub account or allow first-root issuance. Explicit
local adoption can attach account/setup metadata to that exact legacy Owner;
it does not select a guest human or rewrite identity references. A generated
compatibility human is not adoption evidence and cannot be promoted into the
first-root issuer.

The manager role comes from the persisted setup-to-Owner association. A
cryptographic key ID that happens to be the old Control identity is not, by
itself, a manager grant. Encrypted Client `session.capabilities` and the
server-side operation guard remain authoritative. Public capability
availability, a legacy bearer, and possession of the bootstrap signer key do
not override those checks.

First-root eligibility is a durable `ROOT_NEVER_ESTABLISHED` condition for the
configured Owner. Migration seeds permanent root history from every existing
Owner approval key row, including revoked rows. Every future approval-key
insert records history. Revocation does not erase it. If a Root is revoked or
lost, the Hub must not treat zero active Roots as first setup; recovery or a
new trust epoch requires a separate design.

## Local issuance and pairing file

Software 0.0.5 exposes this ordered CLI surface on the local Hub and Owner
machines; the implementation remains a candidate until its required checks pass:

```text
cicada hub setup --owner-label NAME --origin HTTPS_ORIGIN --public-config FILE
cicada owner-signer prepare --profile DIR --connection-file FILE
cicada hub owner-bootstrap-issue --candidate-manifest FILE --candidate-fingerprint FULL_SHA256 --pair-file NEW_0600_FILE
cicada owner-signer bootstrap --profile DIR --pair-file FILE
cicada owner-signer recover --profile DIR
cicada owner-signer grant --profile DIR --manifest-file FILE --expires-at CANONICAL_UTC --output NEW_0600_FILE
```

`hub setup` produces the public connection file containing the locally
verified Client-Control pin. The Owner `prepare` command creates the private
profile and exports its public manifest. The Hub operator reviews the complete
candidate fingerprint and issues the private pairing file. The Owner imports
that file to bootstrap or recover the same proof, then uses the existing
OwnerDeviceGrant path for a Client. Loopback HTTP requires the explicit
`--allow-loopback-http` flag at Hub setup. The connection file carries this
policy for Owner profile preparation; `cicada client prepare` separately
requires its own explicit loopback flag.
This is a Unix local-file flow; it does not claim Android, Windows, or web UI
support.

The local operator first obtains the candidate signer's public manifest from
the Owner's local signer profile. The manifest binds the account and Owner
IDs, the complete Owner public identity and its full fingerprint, the exact
origin, and the independently trusted complete Hub Client-Control identity.
The local issuer verifies that the fingerprint covers the exact candidate,
that setup is `HUB_READY`, the account/Owner/Hub/origin agree, and permanent
root history is absent. The operator reviews the complete fingerprint before
the local command writes a new private pairing file.

The issuer first acquires the StateDir startup lock and checks that a configured
`HUB_READY` setup can issue a first Root, before it constructs `Control` or
loads/creates the compatibility Client-Control identity. It then initializes
`Control` and runs the usual interrupted-Client reconciliation. Keep the Hub
stopped and quiescent while issuing; resolve any interrupted Client operation
through its established recovery procedure first. The command prepares a
pairing file only and does not start the Hub. Start the service through its
existing deployment procedure after issuance. Exact proof recovery after a
lost HTTP response is performed through the running accept route and does not
require reissuing authority.

The issued authority binds all of the following:

- format `cicada.owner-bootstrap.v1`, version 1, and purpose
  `ROOT_SIGNER_BOOTSTRAP`;
- exact account, human Owner, Hub, authority, and operation IDs;
- the complete Owner public identity and full-key fingerprint;
- the exact canonical Hub origin and complete Client-Control Hub identity;
- a Hub-generated reverse encrypted challenge and an expiry no more than ten
  minutes after issuance.

The origin is HTTPS. Development HTTP is allowed only when Hub setup explicitly
enables it and the origin uses a literal loopback IP. The connection file carries
that policy for Owner profile preparation; Client preparation requires its own
explicit loopback option. Userinfo, paths, query strings, fragments, and
redirects are rejected. The pairing file
is private local material, created without overwrite with mode 0600 under a
private owner-controlled directory. It is not a bearer token by itself: it is
bound to the exact candidate private identity and a Hub challenge.

The production CLI requires an interactive review of the complete candidate
fingerprint before it writes the pairing file. The real-TCP integration case
uses the trusted local Store/Control setup and issue APIs to create synthetic
fixture material; it does not claim to test terminal review or the CLI issuer.

Only one live pending authority may exist for the account. An exact request
for the same candidate can recover the same pairing bytes. A different
candidate cannot replace a live authority. An expired pending authority is
retained as history; a later local issue may create a new finite authority
while no Root has ever been established. The authority is not published or
issued through HTTP, a Node, a Client, a bearer token, or a model-facing API.

## Proof and accept operation

The owner-signer profile pins the Hub origin, complete Hub public identity,
account ID, Owner ID, and its own private identity. Before sending, it
validates the pairing file against those pins and invokes an explicit review
callback over the account, Owner, Hub, origin, purpose, authority ID,
operation ID, full candidate fingerprint, and expiry. It opens the Hub's
sealed challenge using the candidate KEM private key, verifies the complete
manifest and challenge, and seals the exact nonce proof with the candidate's
signature key. It durably stores the exact pairing bytes and proof before
network submission.

The only public operation is:

```text
POST /v2/owner/bootstrap/accept
Content-Type: application/json
Body: raw Client-wire REQUEST packet, sequence 1
```

The endpoint has no bearer or legacy manager authorization. Its authority is
the preissued exact pairing plus possession of both candidate private-key
operations. The handler bounds input to 256 KiB. Before post-quantum work it
parses the route and checks the exact persisted authority, request direction,
sequence, operation, sender/receiver IDs and key versions, expiry, setup and
permanent root-history state; for a consumed authority it also checks the exact
proof digest and active Root before returning the cached receipt. Eligible
pending requests then undergo full signature and KEM-possession verification,
with those checks repeated at transaction commit. At most two proof
verifications run concurrently. The request body is
covered by the Hub's current global two-minute read timeout; a shorter
per-operation body deadline is a separate hardening follow-up. The public route
does not accept a candidate key, issue authority, create an account, or enroll a
Client.

On acceptance the server uses one SQLite transaction to insert the public
Owner approval key, record permanent Root history, consume the finite
authority with the exact request digest, and cache the exact encrypted
sequence-2 receipt. The receipt is sealed to the candidate and binds the
manifest digest, authority, account, Owner, key ID, active state, and version.
No Owner private key or proof nonce is stored on the Hub.

| Condition | HTTP result |
|---|---|
| Accepted proof | 200, raw sealed sequence-2 receipt |
| Exact original proof retry after response loss, expiry, or restart, while that Root remains active | 200, byte-identical cached receipt |
| Malformed, empty, or oversized packet | 400 |
| Well-formed but unknown, expired, changed, unauthorized, or invalid proof | Generic 403 |
| Wrong method | 405 |
| Control unavailable or bounded verification slots busy | 503; busy response includes `Retry-After: 1` |

Unknown authority and invalid proof share the same public rejection. An exact
retry is accepted only for the original proof digest and while the matching
public Root remains active. A different proof conflicts. Revoking the Root
disables cached receipt recovery and does not clear root history or enable a
new first-root bootstrap. No automatic cancellation endpoint exists; an
unconsumed authority expires within ten minutes, after which a new local issue
can be made if first-root eligibility still holds.

The signer persists the exact response after authenticating it. If its process
or network loses the accepted response, it reopens the same mode-0600 local
profile and resends the saved proof; `recover` never changes the operation,
proof, challenge, or nonce. This exact retry can obtain the cached receipt
after the challenge expiry if the Hub accepted the proof and that Root remains
active. If the original proof was not accepted and its challenge expires, the
same profile and Owner key may use `bootstrap` with a newly issued,
Hub-authenticated distinct pairing after an explicit review. The signer
accepts that replacement only when the new challenge's conservative signed
issuance lower bound (new expiry minus the maximum ten-minute lifetime) is at
or after the old expiry, and the authority, operation, manifest digest, and
challenge differ. It persists the new exact proof before sending. A replacement
is a new operation, never recovery of the old one; an accepted Root cannot be
replaced, and revocation does not reopen first-Root setup.

## Reuse of existing enrollment

After the first Root is established, the local signer signs the existing
canonical `OwnerDeviceGrant` for the exact Client identity, full fingerprint,
Hub, Owner, purpose `CLIENT_CONTROL`, and expiry. Existing Hub enrollment
validation and encrypted session/Guard remain in force. This bootstrap route
does not perform Client enrollment.

The existing Node device-code, Client `nodes.preview` / `nodes.confirm`, and
INITIAL Node-Control key proof remain a separate subsequent path. A Node
credential, Node identity, or bootstrap pairing cannot establish Owner Root
authority or substitute for the active management Client actor required by
Node confirmation.

## Migration, backup, and evidence obligations

The bounded implementation uses additive Hub schema 60. It preserves schema
59 data and records permanent setup, root-history, and finite-authority state.
The restore validator's exact schema inventory must include all three tables;
restore must preserve the history and consumed receipt needed to prevent
authority reset and to recover an accepted response. A schema-59 binary must
not open schema 60. Existing owner-key IDs, grants, client enrollments, Node
bindings, and role-bearing IDs are not rewritten.

Validation must use a new owned Hub state with a regular mode-0600
`disposable\n` fixture marker. The required Docker gate must start the built
Hub binary as an independent process for the first-root scenario; using an
existing smoke Hub that has already registered a legacy Root does not test
first-root eligibility. Evidence must name the exact source/build identity,
the independent process and SDK scope, response-loss/retry result, revocation
and no-reset result, and cleanup result. Android, native Runtime, physical
device, and public HTTPS results remain separate and must not be inferred from
this protocol test.

## Required negative and recovery checks

The published synthetic protocol vector is
[`owner-bootstrap-v1.json`](../cicada-go/internal/ownerbootstrap/testdata/owner-bootstrap-v1.json);
its [README](../cicada-go/internal/ownerbootstrap/testdata/README.md) explicitly
marks its public test-only private keys **NEVER USE IN A DEPLOYMENT**. The
ordinary test verifies the frozen canonical bytes and should not regenerate it.

The contract is not satisfied unless deterministic or real-TCP tests reject:

- public first-key upload, unconfigured setup, generated-compat promotion,
  or a bootstrap request without a locally persisted pending authority;
- an absent, revoked, guest, or mismatched Owner; a mismatched Hub/account/
  origin; a changed full candidate key; and an existing Root history row;
- wrong purpose or operation, wrong direction/sequence/key IDs/versions,
  malformed ciphertext, altered manifest, altered nonce, wrong signature,
  wrong KEM recipient, replay with a changed body, expiry, and over-limit body;
- a second candidate while a live authority exists, an ordinary Client grant
  presented as Root proof, and a Node credential/key presented as Root proof;
- changed proof after acceptance, retry after Root revocation, restart with
  setup or authority state missing, and attempted re-bootstrap after revocation;
- a legacy crypto identity that has no persisted configured manager mapping
  receiving manager-only Client capabilities or operations.

Tests must also prove success for the exact candidate, a byte-identical cached
receipt after simulated accepted-response loss and restart/expiry, permanent
root-history retention after revocation, configured manager capability scope,
and unchanged Node INITIAL enrollment through existing APIs.
