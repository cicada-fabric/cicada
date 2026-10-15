# Native Cicada App architecture

This document describes the adopted Windows-first user application and its
implementation boundary. It does not declare a release or a completed native
Windows acceptance run.

## Product model

CICADA is operated through three components: Hub, Node and App. A human Owner
is the authority who approves identity and access. Manager handles the Owner's
goals, organization and approvals; Advisor provides bounded recommendations;
Worker performs authorized work. Control is a Hub service that implements
management operations. Control is not the Owner and cannot grant itself
authority. Old `Monitor` and `Client` identifiers remain in some Go packages,
contracts and tests for compatibility; they are not the current product
vocabulary.

The App is a standalone native Windows application built in Go with Gio. Its
ordinary setup, login, Owner-key custody and management workflow must not depend
on a browser or WebView. A browser-based panel exists in the current 0.0.5
source as an earlier account UI and compatibility surface; it is not the
product onboarding path. The target Hub public root URL `/` returns 404 and
does not serve a web dashboard. That retirement behavior is not yet implemented
or validated for all deployments.

Android source is maintained in this repository under `apps/android`, following
its nested `AGENTS.md`. The authorized nonsquashed subtree import preserved its
original Git history; the old source repository is retained without further
development. See the [migration record](repository-migration.md). This layout
change does not complete N1, N2/N3, Android interoperability or native Windows
acceptance; historical results retain their original source attribution.

## Authority and cryptographic boundaries

An account password authenticates an account login only when combined with a
registered App-device PQC challenge. It does not prove Owner-key possession,
activate Root, or create Manager authority. Uploading an Owner public key leaves
it pending. Root activation and management grants require a genuine proof from
the exact existing Owner private key and a separate finite OwnerDeviceGrant
bound to the App device. Existing Owner/account IDs and key IDs must survive
onboarding and migration unchanged.

The Owner root identity and each Hub-scoped App-device identity are separate
records. Imported private keys remain in the App process and encrypted local
vault; only public identities and proofs go to their intended Hub endpoint.
One Hub's vault is pinned to the full Hub public-identity fingerprint, canonical
origin, account and Owner IDs. A second Hub receives a separate vault scope and
must not inherit the first Hub's session, keys or trust.

The Hub identity/account service must decrypt the account operations addressed
to it. Manager instructions are decrypted by Control because Control must
interpret them. The Hub's peer Relay does not receive ordinary peer plaintext;
that plaintext remains at authorized Endpoints. Do not describe these separate
paths as one universal “Hub-blind” property.

NIST application-layer ML-KEM-768 / ML-DSA-65 envelopes protect account and
management messages. HTTPS is a separate transport layer. Native Windows PQTLS
is not implemented or accepted, and a successful HTTPS request does not prove
PQTLS. Windows host and physical administrators are trusted by the deployment
threat model; this design does not require a VM or hardware enclave against a
malicious host administrator.

## Onboarding and recovery target

The final ordinary setup uses a single high-entropy, one-use activation code
delivered through the operator's trusted local channel. It is one encoded or
scannable secret-bearing item, not a JSON document or a collection of IDs and
public-key files to copy by hand; its text representation may be long. The
authority is bound to the exact Hub fingerprint and origin, stable
Owner/account scope, setup epoch, purpose and expiry. The App fetches the Hub's
full public identity itself and verifies the supplied pin before sending the
code or password. The Hub root URL is not an onboarding page.

The first authenticated setup request reserves the exact Owner public identity
and App-device public identity that now exist. The reservation also binds the
key-pair possession proof and operation identity. A retry resumes only that
same candidate and exact request; a changed key tuple is rejected. The finite
authority is consumed once. Network/database transactions do not remain open
while waiting for a person or an HTTP client.

Account credentials, the first account-login device and a pending Owner-public
association are distinct from active Root. The code cannot confer Manager
authority on its own. Final Owner activation requires the imported/generated
Owner private key's KEM and signature proof plus the exact grant for that App
device. A controlled continuation for a legacy Owner must bind the known
persisted Owner/account IDs and exact pending public key; it cannot create a new
Owner or rotate keys to simplify import.

After enrollment, reopening the App must use its trusted encrypted local
profile and must not require the one-use installer code again. Pending encrypted
requests and accepted receipts are saved before network progress is reported.
Only an authenticated PQ response can settle a request: an unsigned HTTP 403,
timeout or restart cannot clear or replace an uncertain pending operation.
Login/session status must be reconciled with authenticated, current-epoch Hub
state before protected management actions resume.

## Checkpoints and current limits

The bounded sequence is:

| Stage | Scope | Current state |
|---|---|---|
| N1 — native foundation | Gio Windows UI source; typed Hub identity verification; account claim/login/inspect/logout; separate Owner and App-device identities; AES-GCM vault and durable exact-packet state; truthful Root/Manager pending state. | Partial in software 0.0.5. The app is not a released installer or an accepted Windows program. |
| N2 — finite Owner activation | Single-code first Root proof; exact legacy `PENDING_PROOF` continuation; automatic profile/restart resume and authenticated error/status recovery. | Not implemented. Do not treat account claim or current CLI/operator setup as this flow. |
| N3 — authorized Hub/Node workspace | Integrate the App with existing authorized Hub/Node status, preview/confirm and Guard contracts; render live state and reconcile actions durably. | App integration is not implemented. Existing Hub/Node APIs and Guard remain the authority; do not rebuild them in the App. |
| N4 — compatibility retirement | Retire browser product surfaces and public Client-facing names after equivalent App behavior; Hub public `/` returns 404. | Not implemented. Preserve frozen wire names and historical evidence. |

The local vault uses AES-256-GCM with an authenticated, scope-bound envelope.
Windows uses current-user DPAPI and protected current-user/SYSTEM ACLs in the
source, but native Windows execution and ACL behavior have not been run. Linux
tests use the password-wrapping backend; it is not the Windows product default.
The strict Owner importer currently accepts unencrypted PKCS#8 PEM only and
checks that its derived ML-KEM/ML-DSA public identity exactly matches supplied
public PEMs before the vault encrypts it at rest. Encrypted PKCS#8 PEM input is
unsupported; do not shell out to OpenSSL or silently rekey an existing Owner as
a workaround. This format limitation is separate from N2: N1 can preserve and
vault an imported identity, while the protocol still cannot use it to complete
Root proof or activate Manager authority. Runtime zeroization is best-effort,
not guaranteed by Go.

The existing Hub/Node status, preview/confirm and server-side Guard APIs remain
the authority for Node operations. N3 is the missing native App read/action
composition and presentation, not a claim that no backend capability exists.

Focused `appvault` and `appkeys` tests, race tests, vet, OpenSSL-generated
synthetic PEM import and Windows amd64 cross-compilation have passed on a dirty
0.0.5 working tree. Those results do not prove native Windows GUI, DPAPI/ACL,
installer, Android, physical-device, public-HTTPS or PQTLS behavior. The
separate [Hub account validation](hub-owner-account-validation.md) covers the
server account protocol and browser harness, not native Windows acceptance.
An earlier App UI cross-build receipt records its exact dirty source and binary
hash under `.cicada-data/native-app-foundation/`; neither that receipt nor a
cross-build alone is an end-to-end App acceptance result.

The software, schema and wire identities remain separate: current source is
software `0.0.5`, Hub schema `61`, frozen Client contract
`client-hub-v1.6.5`, encrypted wire `1`, catalog `55`. The App transition does
not rename or revise those wire identifiers in place. See the [native App
plan](native-app-plan.md), [account validation](hub-owner-account-validation.md)
and [implementation status](architecture-v2-status.md) for current evidence
and retained failures.
