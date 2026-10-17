# Native Pair App implementation checkpoint

[Frozen-source validation](native-pair-app-validation-20261017.md) records the
actual checks, development artifact and unrun acceptance lanes for this change.

This document describes the App consumer of
[the Native Pair contract](hub-native-pair-contract.md). It does not establish
Hub Guard, Store, real Codex Runtime, Windows desktop or deployment acceptance.
The earlier delivered login executable does not contain this implementation.
The A2 Hub preparation checkpoint keeps its public capability unavailable;
this App therefore sends no new Owner proof against that checkpoint. Positive
App actor tests exercise the frozen full contract, not an available deployment.

## App interactions

The existing native controller exposes eight closed local actions: prepare and
confirm two empty slots, read their state, review both actual joined candidates,
approve one exact slot, reject one exact slot, explicitly revoke the pair, and
recover an uncertain operation. Each maps to its dedicated shared wire DTO.
There is no generic management API, protocol change, model invocation or
automatic native-session creation in this App change.

Bootstrap preview starts with the locally confirmed N3 Node binding. The App
does not invent Store credential commitments or control-binding versions.
The shared target validator checks those values in the authenticated Hub
challenge before the App displays or signs its complete bootstrap target.
Consent review checks the retained bootstrap proof, exact Node, both slot
tuples, candidate attestations and key manifests using the shared validators.

The bilingual UI requires separate explicit consent for bootstrap, slot A,
slot B and revocation. Slot review shows both session identities, full candidate
fingerprint/key ID and the binding, generation, revision and lease metadata
covered by the target digest. The controller independently rechecks the current
review ID and exact target before signing. First consent remains waiting;
ACTIVE after the second consent accepts only the plan's two projected membership
revisions, with the remaining slot fields unchanged. A status observation never
turns the App into a generic authorized Manager.

Pair status reads are explicit. Idle rendering does not poll Pair routes.
Changing the review or account context resets local consent controls. Account
expiry/logout hides private Pair metadata and administrative actions while
preserving the pair's independent peer lifetime. It never sends an implicit
revocation. Expired reviews cannot enable signing; restarted observations are
historical until a fresh authenticated operation confirms current eligibility.

## Local identity and independent Node pin

The original Owner/device keys stay in the existing local vault. An explicit
native Save dialog exports only `owner.Public()` as the existing three-field
`e2ee.PublicIdentity` JSON. It contains no private identity, session or grant.
The App preserves existing files by creating a new file exclusively.

After current account authentication the App displays the full local Owner key
ID and the fingerprint compatible with `nodekeys.PeerKeyFingerprint` alongside
Owner ID. A small pure crypto helper implements the same validated public-key
hash, with compatibility tests against that Node API, so the production App
does not link the Node's SQLite implementation. This is the Node peer
pin fingerprint (`sha256:` plus 64 hexadecimal characters), independently
computed from the local vault keys; it is distinct from the N2 Owner fingerprint.
It is compatible with the existing Node `machine trust-owner-key` public-key
input. Establishing the gpu1 Node pin and any service maintenance remain an
explicit user/operator action outside this App implementation.

## Durable requests and recovery

Six bounded encrypted vault namespaces separate original request, ordinary
response, diagnostic request, diagnostic response, compact state and retained
review. The existing per-namespace 1 MiB and total vault limits are unchanged.
The App never stores a giant reconcile response together with another decoded
copy of its nested receipt in the same record.

The controller seals and CAS-persists the original DTO, packet and immutable
identity/Node target before POST. It authenticates replies against that exact
original and pinned Hub, then persists the raw reply before applying any result.
CAS failure prevents memory-only continuation. Crash recovery applies saved
receipts idempotently and does not restore live administrative permission.

After a lost response, manual recovery first retries the exact original bytes.
Unsigned HTTP errors and malformed responses retain the original. A detached
reconcile uses the same original packet/target, independently of live session,
Root or Node availability. Only an authenticated matching receipt or permanent
no-effect fence settles a mutation. An expired diagnostic may get a fresh
diagnostic request ID, nonce and timestamp; the business original is unchanged,
and a late response to the superseded diagnostic cannot complete its replacement.
There is no unbounded retry loop and no ABSENT-as-success path.
Known-pair rejection uses the shared dedicated fence and original DTO/packet
target validator. A generic result cannot replace its no-effect proof, and an
outer reconcile outcome cannot contradict its nested authenticated fence.

## Verification scope

App-local tests use real shared PQ envelopes, Owner proofs and encrypted vault
CAS with a scripted HTTP actor. They separately test original persistence before
POST, explicit per-slot consent, projected activation, rejection, invalid target
revisions, lost-response recovery without duplicate consent, capability absence,
reopen/CAS boundaries, late diagnostics and public-only key export.

These tests do not establish actual Store/Guard authorization, two real Codex
threads, Runtime/tool delivery, Windows Save-dialog/DPAPI/ACL operation, visual
legibility, public HTTPS or physical acceptance. Those results must retain their
own tested source and artifact provenance. Cross-compilation is a build check;
the known user-reported Windows text-rendering issue remains a separate result.
