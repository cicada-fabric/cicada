# Native App plan

This plan describes the Windows-first native App inside the CICADA Go monorepo.
It does not change the independent Android repository or claim native Windows
acceptance. “App” is the current product name; older Client-facing wire names,
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

An Android repository history-preserving subtree import is an optional,
separate repository-maintenance decision. It is not part of N1 and must not be
performed by copying its source tree or rewriting its history.

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
