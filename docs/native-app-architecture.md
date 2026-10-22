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

## Composable installation and shared authority target

2026-10-19 product direction, with the 2026-10-20
[feedback ledger](native-app-plan.md#current-feedback-and-acceptance-ledger)
tracking implementation and acceptance separately. C0.1 freezes the new
registration crypto/wire contract; it does not implement this whole target.
The existing Pair flow has a separate
[user-reported same-Node batch](native-app-validation.md#2026-10-20-user-operated-same-node-pair-batch),
including both communication directions and continuation after closing App.

Hub, Node and App are optional components that may coexist on one host. A
device is the UI entry point; authentication identifies a controlled installation
and its persistent component keys, not unique physical hardware. Component
actors keep independent keys; co-installation grants no authority or shared
Owner private key, and introduces no global master key or new daemon.

Registration and business authorization are separate. Pending/registered
installations gain only minimum self-authentication/own-status from registration
and may separately hold zero or more exact business grants. An Owner panel
prepares authorization; Hub verifies and durably records it, while Node-local
Guards enforce current signatures, scope, epochs and bindings. Network/Group/
Thread membership, peer and execution rights need their own grants. Installing
another role does not expand grants. A human device code locates one request;
proofs, approval and secret credentials remain separate. First-Hub Root retains
independent controlled bootstrap; registration cannot claim or reopen Root.

Hub is authoritative for Hub-scoped shared configuration, device/component
registrations, permissions, task orchestration state and shared audit, durable
across restart. Node retains private credentials, crypto/replay state and its
execution ledger; peer plaintext stays at authorized Endpoints. App provides UI,
local authentication/signing and protected profiles plus a durable original-packet
pending/outbox record; this record is not disposable cache. App is not the
resident business controller.

The required lifecycle boundary is that closing App1 sends no network revocation
and logout ends only its account session. Closing-window continuation is
USER_REPORTED_PASS; logout and adversarial lifetime cases need separate evidence.
Future component removal must retain protected identity and unresolved original-request
material and preserve unrelated Hub/Node programs, services and state. It must
not revoke the Hub's App-device registration. Deleting retained data and explicitly revoking
a Hub device are separate actions. Existing authorized Node/peer work retains its
original limits. Expiry and explicit device/epoch/grant revocation still apply,
including dependencies on the original App-device identity. App2 registers
independently, receives exact authorization and reads Hub's shared state without
copying App1's local data or private identities. This remediation stage does
not develop uninstall scripts; these removal requirements remain future targets.

Owner's long-lived identity is independent of any one App installation. Signing
keys stay in controlled local custody, never uploaded to Hub. If all copies of
the sole Owner signing key are lost, recovery remains **NOT_IMPLEMENTED**;
a new App/password cannot restore Root. See the [future acceptance targets](native-app-plan.md#composable-installation-and-shared-state-acceptance-target).

## Three-stage installation and Node connection

2026-10-22 user direction; **IN_PROGRESS**. The stages are download/install,
explicitly start the Node daemon, then install/connect the Codex plugin to that
running Node. The existing component file installer already leaves services,
enrollment, grants and product state unchanged; the resident Node agent already
exists. The work in progress supplies the formal local connection configuration
and discovery needed between those components. It does not add another Node
daemon, broaden C0 registration or implement a general installer/uninstaller.

The file-only installer materializes the repository's single existing
plugin asset set using the selected absolute executable and explicit
`--user-root`. MCP and Hook consumers use the same selected-root
resolver, without inheriting deployment choices from a terminal or shared Codex
daemon environment. Plugin installation may make the MCP frontend available;
neither installation nor that frontend starts the resident Node or registers
an identity. Only the user's separate Node-start action starts that daemon.

Discovery uses private locator hints under the selected root and a live
description from the selected running Node, with same-UID checks and renewed
verification of the configured identity/pins. A locator file or reachable local
endpoint alone proves no authority. Missing/stale discovery, a stopped Node or
ambiguous Node selection must report offline/unavailable or require explicit
selection, without starting a Node, creating credentials, silently re-registering
or choosing another Node/Hub. Reconnection retains the original selected root,
state, identities and current authorization limits. Runtime-context proofs and
Hub/Owner Guards remain separate requirements for business operations.

Hub/Node owns discovery and its trust boundary; App owns file-install
materialization and consumers. A [bounded actual Linux gate](native-app-validation.md#2026-10-22-persistent-codex-daemon-three-stage-acceptance)
now passes installation/plugin update through the same existing Codex daemon,
Node offline/start/stop/restart and original-pin recovery on the integrated
source. Existing root mode 0755 and its canary remain unchanged. Rollout and
remaining platform/adversarial observations are still IN_PROGRESS/NOT_RUN; see
[three-stage acceptance conditions](native-app-plan.md#three-stage-installation-and-node-connection).
The earlier startup failure and external launcher stdio check retain their
[historical scope](native-app-validation.md#2026-10-22-installed-plugin-mcp-startup-failure-and-isolated-launcher-check).
That temporary launcher has not been applied to the real environment and is
not the implementation of this three-stage flow.

## Naming, Directory and native-context targets

The 2026-10-22 [Node/user/Network acceptance preparation](native-app-plan.md#nodeusernetwork-policy-acceptance-preparation)
separates trusted same-UID host context from Hub-authoritative business grants.
The target permits local collaboration within an explicitly approved domain
without per-Thread Pair approval; the new grant/consumer contract is pending.
Actual other-UID IPC/key/context protection, domain expiry/revocation and legacy
Pair migration require separate evidence. Parameterizing an existing Codex
daemon's writer umask or creating fresh A/B is acceptance preparation only;
it implements neither that policy nor a record-permission repair.

The 2026-10-20 feedback is tracked in the
[existing acceptance ledger](native-app-plan.md#current-feedback-and-acceptance-ledger).
The following product targets are implemented in stages under the
[bounded Endpoint/directory contract](native-endpoint-directory-contract.md).
Backend, actual App/Node consumers and physical UI have separate acceptance.

Endpoint IDs remain stable internal identity. Ordinary lists lead with name,
workspace, Node and current status, while retaining the original native SID,
Endpoint ID, workspace and name. Labels and workspace paths confer no authority;
renaming cannot change keys or permissions. Duplicate names, including matching
name/workspace pairs, require explicit disambiguation and selection. Selection
binds the exact internal ID and current version; a revoked selection fails
instead of resolving to another Endpoint with a similar label. Removing an
Endpoint association must not delete the original Thread or its workspace.

Lists on the current machine still require this Owner's or the caller's exact
authorized scope. Cross-Owner discovery does not disclose absolute workspace
paths by default. A qualified Owner may see registered objects with no granted
communication rights; the UI must distinguish registration from authorization.
Hub persists inventory and permissions; App is not their only store. Permission
presets must still follow the genuine Owner signing-key chain and current Hub/
Node Guards. A selected name, policy preset or account login is not a grant.

The backend at `d3acd4bfe6f3f10867db6a5e3ae432f8477d9748` reuses zero-right
Endpoint registration and same-Owner topology/Directory with cross-Owner
redaction. Registration preserves the original SID/Endpoint/Principal/name/cwd,
starts offline and creates no native SessionBinding, lease, key or membership.
Repeat registration is read-only; changed cwd conflicts and `left` is not revived.
Leave uses the original authorization-state digest and current Node fence.
The independent finite `owner.endpoints.read` proof leaves the old N2 two-operation
allowlist unchanged. Its result is a private bounded snapshot, never communication
authority. Node local-bridge source `97d8a1d22643ddf911c8842ac9f95802928189df`
and actual App Core read source `07bd265c69d99119d87bdfa6204c27d0273ef14c`
are integrated. The actual App signs its own bounded reads, retains uncertain
original packets across child/Hub restarts and displays authenticated
`SNAPSHOT_ONLY` cards. Public capability availability can be false after restart
while the original authenticated snapshot remains valid; recovery must not require
a new GET or Owner signature. These have [source-bound independent scopes](native-app-validation.md#2026-10-20-actual-app-owner-directory-integration),
with no general management/canvas or communication authority. Bounded actual
installed-plugin register/peers and Host context now have independent Linux
[execution evidence](native-app-validation.md#2026-10-20-actual-installed-plugin-pty-and-host-mcp-context).
A separate [actual cold-lease gate](native-app-validation.md#2026-10-20-actual-default-five-minute-cold-lease-and-current-revocation)
passes named connects and signed App identity matching, dual consent, original
default-five-minute Node lease renewal/restart before the first joined Host
tool, and current revocation. It uses an explicit manual Owner public pin;
automatic delivery is pending. Operator faults, Leave, extended expiry/privacy,
native model/queue consumption and physical Windows remain separate pending scopes.
This does not activate
the frozen broader C0 installation-registration family. Zero-right registration
does not require an existing Pair; reserved-Pair communication retains its
separate Join, slot and consent requirements.

Native plugin integration must obtain the actual original Thread context,
validate its native record/workspace and retain the existing Node-side check.
The tested manual exact-resume procedure is a bounded workaround: connected MCP
tools alone do not prove a SID, Join or authority. Current literal registration
and directory actions use the actual native record and Node bridge without a
model decision. Named reserved-Pair connect now has the bounded actual cold
gate above; Leave and original-intent recovery still require their own actual gates. No new installed launcher, daemon, guessed SID or
unrestricted model-provided identity field is implied by this target.

Owned probes of actual Codex 0.163.0 establish a narrower host mechanism:
literal UserPromptSubmit hooks can finish synthetic local commands without a
provider call, and PreToolUse can replace declared MCP arguments with the actual
session/cwd/call context. An actual fork receives a distinct session ID and the
replacement reaches the mock MCP. Missing or failed hooks can pass through;
the mock sink's rejection does not establish a product Guard. The production
adapter must independently validate its short-lived, per-call original context
and refuse missing, stale, replayed or cross-Thread tickets. Subagent hooks can
carry the parent's session ID; it must not be used as a child native identity.
The later product consumer at `18868ba`, asset correction at `c3a1517` and
Codex-0.163-compatible single legacy bundle at `1ca85b5` have distinct sources.
Actual normal trust and literal register/peers execute through the real Node;
a real Host MCP call echoes its advertised unique nonce, receives a Node-issued
per-call ticket and reaches the unjoined business refusal. The actual App
independently signs the matching name/cwd/offline directory card. Missing or
forged context and restart nonce refusal have a separate seven-event scope.
These do not prove valid-ticket replay/expiry, A/B heartbeat switching,
clear/subagent behavior or a joined conversation. After the presentation fix at
`fcea942`, the actual cold gate verifies that each literal result body appears
once in the current viewport. The SDK still displays a `Blocked by hook` heading;
that remains a UX limitation, not a native picker acceptance. The earlier
duplicated-body observation retains its original source in validation.

Cicada-owned installed user files default to `~/.cicada`, with an installation-
selected custom root. Existing platform vault and Node locations are not
silently migrated, replaced or rekeyed. Root selection and restoration must
locate the original protected identities and unresolved requests, including old
nested vault layouts. See the [path rule](native-app-plan.md#installed-user-file-root).
Partial source `73d6f9ad13c26ad7cf203e2924adcc7a46104213` covers new App/Node/MCP
defaults, custom App root selection and component file-prefix defaults; authenticated
recovery retains original sources. Hub/workspace/cache defaults and migration
remain separate pending work, and physical Windows execution remains NOT_RUN.
Native navigation, summaries/details, legible CJK text, selectable/copyable
public fields and actionable recovery are product acceptance requirements;
they do not justify exposing private keys, secrets or signed-out workspace data.

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
| N2 — finite Owner activation | Single-code first Root proof; exact legacy `PENDING_PROOF` continuation; automatic profile/restart resume and authenticated error/status recovery. | Hub/App core implemented under `owner-activation-v1`, schema 62; independent Linux protocol gate SCOPED_PASS (131 test events, zero failures/skips). Dedicated native Windows security remains NOT_RUN. See the [contract](hub-owner-activation-contract.md) and [receipts](native-app-validation.md#n2-hubapp-integration). |
| N3 — authorized Hub/Node workspace | Compose existing Hub/Node Guard, explicit Node preview/confirmation, target-only status and durable recovery in the native App. | Bounded `app-node-authority-v1` App core/UI and `serve --hub-nodes-only` implemented, schema 63. Latest reviewed `854a594` plus dirty QA inputs: Linux 84/0/0 and separate automatic status-entry 2/0/0, SCOPED_PASS. Earlier Ubuntu 24.04.4 84/0/0 retains its own source. Earlier Windows automatic decay failed; the later 1980dce batch reported stale/online recovery passing. The 2026-10-20 Pair batch reports Joins, dual consent, bidirectional ASK/Reply and window-close continuation passing, with independent traces still NOT_RUN. Live canvas, App SSE, native Runtime and physical acceptance remain incomplete. See the [matrix](native-app-plan.md#n3-independent-safety-model-and-acceptance-matrix) and [receipts](native-app-validation.md#n3-idle-decay-and-automatic-status-follow-up). |
| N4 — compatibility retirement | Retire browser product surfaces and public Client-facing names after equivalent App behavior; Hub public `/` returns 404. | Not implemented. Preserve frozen wire names and historical evidence. |

The local vault uses AES-256-GCM with an authenticated, scope-bound envelope.
Windows uses current-user DPAPI and protected current-user/SYSTEM ACLs in the
source, but native Windows execution and ACL behavior have not been run. Linux
tests use the password-wrapping backend; it is not the Windows product default.
The strict Owner importer currently accepts unencrypted PKCS#8 PEM only and
checks that its derived ML-KEM/ML-DSA public identity exactly matches supplied
public PEMs before the vault encrypts it at rest. Encrypted PKCS#8 PEM input is
unsupported; do not shell out to OpenSSL or silently rekey an existing Owner as
a workaround. N2 can prove the exact supported imported identity and enroll its
App device with a separate finite lease. It does not grant general Manager
authority. Runtime zeroization is best-effort,
not guaranteed by Go.

The existing Hub/Node status, preview/confirm and server-side Guard APIs remain
the authority for Node operations. The bounded N3 App composes those operations:
an already proved ACTIVE Root signs new, finite consent bound to the exact
account login, App, Node candidate and grant head. INITIAL permits one
`nodes.confirm`; a later explicit READ_EXISTING instance permits only status of
the same confirmed binding. Neither renews N2 or confers general management
permission. Public capabilities describe availability and never authorize a
caller. See the [contract](hub-app-node-authority-contract.md) and
[identity/Node-only service](hub-nodes-only.md).

This service retains the existing identity, Client-Control and Node-Control
keys and performs deterministic identity/Guard operations with Control inference
disabled. Accepted relay heartbeats establish only bounded Node freshness;
they do not establish Worker availability, an App SSE connection, model
availability or native Runtime execution. A newly approved Node without a valid
heartbeat for its current binding is UNKNOWN. After a Node stops, its last
accepted heartbeat remains CONNECTED until the original 120-second deadline,
then becomes STALE. Cached observations decay against that heartbeat time.

The saved Node card is a persistent connection fact. Account sign-in and the
App's finite status access can expire without reinstalling or re-pairing that
Node. Current status, saved binding and current permission are shown separately;
expired access does not mean the Node left the Hub. Explicit device, key,
credential or binding revocation still applies. Actual relay-only restart after
App self-cancellation preserves Node identity/credential and commits a later
heartbeat; continuation across a full natural fifteen-minute N3 lease expiry
has not been run.

The native renderer schedules the earliest relevant deadline and immediately
resamples a still-live snapshot that crossed its deadline during layout.
Historical expired fields do not keep requesting frames. With an existing
valid login and selected-Node grant, the App also schedules a status read every
30 seconds. This is polling, not App SSE. The Core checks the exact target and
full binding under its action lock, persists each encrypted request before
POST, and never renews a grant or confirms another Node. Unknown/stale liveness
does not prevent a read while authority is still valid.

Foreground controls run before a due background read. Once a read starts,
manual operations including profile changes share its short busy period; its
context budget is at most ten seconds and never exceeds remaining authority.
There is no foreground preemption or queue. Minimizing pauses future ticks;
closing cancels the read. Unauthenticated or uncertain outcomes retain the
original packet and stop new automatic requests until explicit recovery and
fresh inspection. Portable Gio Router tests and real Core/TCP tests cover these
layers; they do not establish the new artifact's Windows event-loop behavior or
exclude Windows clock skew in the reported defect. The older `e426` package has
user-reported Windows/public-HTTPS/physical Ubuntu initial binding and heartbeat
observations, plus Root's read-only process/binding observations. These partial
results do not establish corrected Windows automation, full native security or
visual review, Node user-service/reboot or full-lease continuity.

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
software `0.0.5`, Hub schema `63` (N2's introduction was schema `62`), frozen Client contract
`client-hub-v1.6.5`, encrypted wire `1`, catalog `55`. The App transition does
not rename or revise those wire identifiers in place. See the [native App
plan](native-app-plan.md), [account validation](hub-owner-account-validation.md)
and [implementation status](architecture-v2-status.md) for current evidence
and retained failures.

## N2 independent threat model

Preparation started from clean source `c1b6a30`. The frozen additive contract
is [owner-activation-v1](hub-owner-activation-contract.md); Hub and App source
and actual test manifests are pinned separately in the [validation record](native-app-validation.md#n2-hubapp-integration).
Existing account claim and operator first-signer bootstrap remain distinct
protocols. Their success does not establish native N2 completion.

Assets are the stable Hub/account/Owner IDs, exact existing Owner keypair,
separate App-device keypair, finite setup authority, current epochs, grants,
encrypted pending packets and immutable authenticated receipts. The trusted
computing base includes the local operator delivery channel, App key custody,
Hub identity/authorization service and its persistent database. Control
inference and public capability discovery cannot issue authority. Host
administrators are trusted; compromise of their host is outside this scope.

An attacker may control DNS/transport or an HTTP intermediary, copy an expired
or consumed code, own a different Owner/App keypair, possess an account password
without the enrolled device, race candidates, replay accepted packets, tamper
with signatures/ciphertext, and induce connection loss or process death. A
stolen valid, unused setup secret is authority within its deliberately finite
scope; secrecy of the trusted local channel is an explicit assumption.

| Boundary | Required invariant and negative oracle |
| --- | --- |
| Operator material → Hub discovery | App independently recomputes the full public-identity pin at the exact canonical origin before any secret-bearing POST. Wrong key, scheme, origin or pin sends zero secrets. |
| Setup authority → candidate reservation | Purpose, expiry, setup epoch, Hub/account/Owner and both public identities are bound atomically. Two distinct candidates have one durable winner; changed tuple/request cannot resume it. No transaction waits for a person or a remote client. |
| Account → Root | Password plus enrolled App proof creates only an account actor. A pending public Owner association, cached receipt or public capability never activates Root or Manager. |
| Owner proof → App authorization | Exact existing Owner KEM and signature proofs plus a finite, correctly scoped OwnerDeviceGrant are independently verified. Missing proof, foreign Owner, wrong App, forged grant and stale epoch leave authority unchanged. |
| Local vault → network | Commit the exact encrypted request before sending. Lost/unsigned/corrupt responses preserve uncertainty. Restart retries the original bytes; it cannot silently reseal, replace identities, clear pending state or infer success. |
| Durable receipt → current authority | Exact receipt recovery does not revive revoked Root, device, grant or epoch. Reconcile authenticated current Hub state before protected management actions. |
| Existing deployment → continuation | Preserve exact existing IDs and pending key. Reject unknown candidates, second Owner, implicit rotation and resurrection of revoked Root. |

The enrollment grant lasts at most ten minutes. The separate runtime lease
lasts exactly 15 minutes from challenge issuance, allows only `nodes.list` and
`session.capabilities`, and cannot renew itself. Neither proof completion nor
its cached receipt creates an account session. Ordinary login is independent
of Root/lease availability: an ACTIVE account device can log in for account
diagnostics after Root or lease revocation, while current server Guards still
deny protected operations. Account-device revocation remains authoritative.

A signed terminal rejection/cancellation can permit trusted operator material
for the same complete scope without changing local keys or device ID. Unknown
operations, rollback of epochs, a different Hub/account/Owner, and established
or revoked Root cannot use that replacement path. Signed `ABSENT` means no
receipt was observed; it does not fence a delayed original and cannot clear
uncertainty. Account reconciliation instead records a durable operation/digest
fence before allowing a replacement request.

The fault driver must distinguish connection loss before acceptance from loss
after a durable commit. Evidence records request/response hashes and assertion
names only; codes, passwords, session tokens, private keys and complete proof
or packet payloads remain in disposable private fixture state. Linux password
vault tests cannot establish Windows DPAPI/ACL or GUI behavior.

## Login-first display boundary

The login-first change protects saved Hub/account/Owner/Node metadata from
display before current account authentication. Its preparation baseline is
`5fee32c`; independently reviewed implementation is `1980dce`. This is a
presentation boundary inside the trusted App process;
it does not protect a compromised host or replace encrypted vault custody,
cryptographic verification or server authorization. Implementation review and
execution evidence are recorded separately in the [matrix](native-app-plan.md#login-first-presentation-safety-matrix)
and [validation record](native-app-validation.md).

A cached profile, saved Node binding, Root state or historical receipt cannot
open the workspace. The display decision consumes the Core's authenticated
snapshot: a verified exact Hub and nonempty account/Owner/device scope, one of
SESSION_ACTIVE, OWNER_READY or OWNER_PROOF_PENDING, and an explicit canonical
future session deadline. Trusted profile recovery must complete fresh server
inspection in this process before the Core publishes these account states.
This preserves existing valid-session restoration; it adds no requirement to
enter a password on every launch. Account authentication remains independent
of Root proof, finite Node status permission and Manager authority.

Before that decision succeeds, the root renderer must use a reduced snapshot
and a separate public branch. Saved identity values, pins, session/grant/Node
deadlines, Node observations, details, canvas and preview cannot be shown by an
alternate child widget. A saved-profile selector uses neutral numbered labels
while retaining the exact trusted profile locator internally. User-entered
credentials never select an origin or bypass the existing full-pin check.

Account recovery has priority over a new login. An uncertain Node request may
also need a neutral recovery entry before login; it retains the original
encrypted request and receipt semantics without disclosing Node identity. A
Node-only pending read during a still-valid account session does not close the
workspace. Necessary first connection, exact Owner import/proof and activation
remain reachable through the existing setup flow.

Logout, authentication loss and complete scope changes clear transient inputs,
consent and expanded/preview state without erasing keys, bindings or pending
requests. Stable unauthenticated frames must not repeatedly clear typed input.
The hidden screen pauses future Node polling; in-flight recovery and session
inspection keep their existing Core guards. Showing a workspace never adds an
AvailableAction, renews a grant, proves Root or authorizes a Node operation.
Portable tests and source review cannot establish Windows GUI, DPAPI or ACL
behavior; new-artifact physical execution remains NOT_RUN until recorded.
