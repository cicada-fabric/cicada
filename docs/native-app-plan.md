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
| N2 — Owner proof and finite activation | Reuse exact existing Owner keys; one-use local activation code; server-authorized Root proof; finite App lease; controlled pending-Owner continuation; trusted profile restart and authenticated recovery. Account login alone never activates Root. | Hub/App core implemented under [owner-activation-v1](hub-owner-activation-contract.md), schema 62; independent Linux protocol SCOPED_PASS (131 events, zero failures/skips). Oct 17 Windows initial flow/positive ACL are user-reported PARTIAL; dedicated native security tests and comprehensive visual acceptance remain NOT_RUN. See [validation](native-app-validation.md#n2-hubapp-integration). |
| N3 — Authorized live canvas and Node actions | Add live objects only from an authenticated, authorized Hub/Node read path; add explicit guarded Node actions and status reconciliation. Empty/unavailable canvas stays empty; no demo objects are presented as live state. | Bounded Node enrollment/status/recovery under `app-node-authority-v1`, schema 63. Reviewed `854a594` plus dirty QA: Linux 84/0/0 and separate automatic status-entry 2/0/0; earlier Ubuntu 84/0/0 retains its source. Windows `1980dce` batch steps 1–5/8 are USER_REPORTED_PASS; second-instance entry and Chinese text are USER_REPORTED_FAIL. Independent native execution remains NOT_RUN. Next priority is two real Codex Threads on the same gpu1 Node; workspace/task creation is paused. Live canvas, App SSE and native Runtime acceptance remain incomplete. |
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

The historical N1 restart path required the same unexpired secret-bearing
claim code for an initial claim, or the same still-valid public connection card
for an existing account. N2 adds authenticated local-profile discovery and
resume without installer material, Root completion and exact pending-Owner
continuation. Historical N1 receipts retain their original limited scope.

## N2 independent acceptance matrix

The independent driver is `scripts/test-native-app-n2.sh --require-n2`. It uses
real ML-KEM/ML-DSA/AES-GCM, loopback TCP, persistent SQLite, encrypted Linux
vaults and separate Hub/App-core processes in disposable Docker. No Control
inference service runs in the independent fixture. The table maps obligations
to actual tests; the [run receipt](native-app-validation.md#n2-hubapp-integration)
determines their result. It does not transfer Linux results to Windows.

Test names below abbreviate `TestN2Activation` as `A:`, `TestN2Account` as
`C:` and otherwise use the complete test name. Independent tests live in
`cicada-go/acceptance/n2`; `server` and `store` explicitly identify narrower
production-package guards. Full names and every required subcase are enforced
by `scripts/native_app_n2_evidence.py`.

| ID | Fault or boundary | Required observation | Tests and evidence boundary |
| --- | --- | --- | --- |
| N2-01 | Wrong full Hub public key/pin | Reject before secret POST/vault creation | `C:PinAndExpiryBeforeSecrets`; `A:PinAndConsentBeforeSecrets/wrong-full-pin` |
| N2-02 | Expired finite credential | Independent local and server expiry rejection | `A:PinAndConsentBeforeSecrets/expired`; `A:ExpiredProofAndCancelledMaterial/expired-real-credential` constructs a short valid credential through the trusted Store issuer, waits in real time, then sends the original encrypted packet |
| N2-03 | Consumed credential, exact duplicate and changed request | Exact durable receipt; changed request fails | `A:ConcurrentDistinctClaimsAndExactCompletion`; `C:ConcurrentClaimAndConflictingReplay`; `A:ReplacementAfterFencedCancellationPreservesKeys` additionally checks safe operator replacement after a signed terminal result |
| N2-04 | Concurrent distinct candidate claims | One durable candidate wins | `A:ConcurrentDistinctClaimsAndExactCompletion` and `C:ConcurrentClaimAndConflictingReplay`; the former also runs under `-race` |
| N2-05 | Wrong Owner/account/Hub scope | Hub rejects independently of local preflight | `C:ForeignScopeAndMissingDeviceProof`; `A:CryptographicNegativeGuards/wrong-owner-scope`; real lower-level encrypted packets bypass local body preflight |
| N2-06 | Missing Owner KEM/signature proof | No Root, credential, enrollment or lease effects | `A:CryptographicNegativeGuards/{missing-kem,missing-owner-signature,wrong-owner-signature}`; actual Hub rejection plus reopened database assertions |
| N2-07 | Forged/expired/wrong-purpose grant | No unauthorized enrollment | `A:CryptographicNegativeGuards/{forged-grant,wrong-grant-purpose}`; real short proof window in `A:ExpiredProofAndCancelledMaterial`; server `TestN2ExpiredGrantChallengeCannotActivateRoot` |
| N2-08 | Stale setup/account/device epochs | Historical receipt never revives authority | `A:CryptographicNegativeGuards/stale-account-epoch`; `A:ExpiredProofAndCancelledMaterial/cancelled-material-and-late-request`; `A:HistoricalReceiptNeverRevivesCurrentAuthority`; `A:AppRestoreEpochSettlesOldReceiptWithoutRevival`. Isolated SQL epoch fault is not a full backup/restore run; store `TestN2RestoreFencesLeaseAndPreservesCredentialAndRoot` calls the real restore fence |
| N2-09 | Unknown/substituted App | Password/public capability never bypass exact device | `C:UnknownDeviceCannotUsePassword`; `A:CryptographicNegativeGuards/wrong-app-key`; server `TestN2ClientDispatchAndCapabilitiesIntersectFiniteLease` tests actual dispatch allowlist/login guards |
| N2-10 | Lost response, unsigned 403, corrupt PQ response | Authenticated settlement only | `C:ProcessRecovery` covers six account operations × four faults; `A:AppProcessesAndLargeStatusRecovery` covers prepare/complete/status × three faults, including actual nested receipt larger than 96 KiB |
| N2-11 | Kill Hub/App and reopen persistent state | Original bytes, IDs and keys survive | `C:ProcessRecovery`; `A:AppProcessesAndLargeStatusRecovery`; `A:ConcurrentDistinctClaimsAndExactCompletion`. Child Hub/App are actually killed and restarted; not just controller recreation |
| N2-12 | Same operation ID/different ciphertext or nonce reuse | Reject conflict; keep original receipt | `A:ConcurrentDistinctClaimsAndExactCompletion`; `A:CryptographicNegativeGuards/reused-nonce`; `C:ConcurrentClaimAndConflictingReplay` |
| N2-13 | Account versus Root; Control inference off | Independent account flow; no general Manager authority | `C:ProcessRecovery` finishes claim/login/inspect/logout with Root pending; all independent activation fixtures omit Control; post-proof App tests require separate login and keep Manager unavailable |
| N2-14 | Exact legacy pending Owner | Keep credential, IDs, public key and old device | `A:LegacyImportedOwnerKeepsCredentialAndIDs` imports four real OpenSSL synthetic PEMs; tests unknown replacement Owner at Hub; server `TestN2LegacyContinuationRetainsPendingOwnerCredentialAndDevices` |
| N2-15 | Profile reopen without installer code | Authenticate saved profile and current Hub state | `A:AppProcessesAndLargeStatusRecovery`; helper removes installer material on every profile reopen; `A:AppRestoreEpochSettlesOldReceiptWithoutRevival` checks obsolete session recovery |
| N2-16 | Vault failure before send | Zero POSTs; no memory-only continuation | `A:VaultFailureBeforeSend` uses a deterministic path/persistence failure; existing App guard complements it |
| N2-17 | Two Hub scopes | Distinct keys/profiles; no inherited session | `A:TwoHubVaultScopesRemainIndependent` uses two real TCP Hubs and one encrypted-vault root |
| N2-18 | Windows DPAPI, ACL and GUI | Native execution receipts required individually | Oct 15 automated native execution NOT_RUN. Oct 17 user-reported initial GUI flow and positive ACL inspection PARTIAL; synthetic native DPAPI/ACL driver is separate and awaits execution. See [dated observations](native-app-validation.md#windows-native-security-driver-and-user-observations--2026-10-17) |
| N2-19 | Finite lease expiry/late old receipt | No renewal or revival | `A:AppClockExpiryDoesNotRenewLease` advances App `Config.Now`; store `TestN2LeaseGuardExpiryScopeAndExactHistoricalRecovery` uses logical time/past lease. Oct 17 natural expiry UI is user-reported; precise elapsed-time and new-operation Guard receipts remain NOT_RUN |
| N2-20 | ABSENT and late original | ABSENT cannot settle uncertainty; durable fence can | `A:AbsentStatusKeepsPendingUntilLateOriginal`; `C:ReconcileFencesLateCorrectRequestAcrossRestart` races under `-race` too; server `TestN2AccountReconcileRacesOriginalWithoutLateCommit` |
| N2-21 | Wrong password then correct password | Signed fence allows safe re-login | `A:AppWrongPasswordFenceAndRelogin`; server `TestN2AccountWrongPasswordAndExpiredSessionRecoverWithDurableFence` |
| N2-22 | Expired/revoked session and account epoch change | Re-login independent of revoked lease; no old-session revival | `A:AppWrongPasswordFenceAndRelogin` injects persisted session revocation; `A:AppRestoreEpochSettlesOldReceiptWithoutRevival` keeps the lease revoked after new login; server test above injects a past account-session expiry and sends the saved packet over real TCP |
| N2-23 | Native interaction and visual quality | Smooth, legible real desktop setup/recovery; no secret disclosure in snapshots or error UI | Oct 17 initial native GUI operation user-reported PARTIAL; comprehensive visual/interaction review remains NOT_RUN |

Each run must record source manifest before/after, dirty status, builder image
ID, test binary hash, selectors, individual exit codes and skips, resource
ownership/cleanup and artifact hashes. No selector match, missing prerequisite,
skip or unimplemented row is a pass. Default baseline success is a scoped
result only; `--require-n2` returns zero only for its complete declared Linux
scope, with every expected test present and zero failures/skips. Prerequisite
failure returns 2; gate failure returns 1. Physical NOT_RUN rows remain separate
even when that scoped gate passes. Android, native Runtime, physical device, public HTTPS and native
PQTLS are separate NOT_RUN scopes.

## N3 independent safety model and acceptance matrix

N3 was authorized on 2026-10-17 from clean `f8b5e58`. The first Node target is
Ubuntu **24.04.3 x86_64/amd64**, ordinary user **zyf / UID 1000**, Codex
**0.163.0**; Windows App remains x64. These are target requirements, not
observations that those programs have run. ARM64, installer/root relocation,
N4 and broad business/runtime acceptance are outside this checkpoint.

Hub owns the shared protocol and production Guard; App owns the production
controller/UI. Independent acceptance owns `cicada-go/acceptance/n3`, its
disposable driver/evidence and this matrix. The integration owner reviewed `app-node-authority-v1` types at
`a545988ac6c038da180413d4f29ffbf740c402d4`, then shared proof/framing helpers at
`5f509befa6065ac41abeb23451ef8d41cc2c76aa`. The Store checkpoint is
`e078c58d97413f5e0457acb3c586afbef1a9d438`, schema **63**. The production App controller was reviewed at
`8df8ae5034f819ff3d839b6574f02c3c887af253`, followed by actual Hub/HTTP/CLI runtime
`af92b16d3c0dc616280d694986692a2cbb1caa71`, phase **HUB_NODES_ONLY**.
The runtime fixes were reviewed at `ec72bf2891bcc7bf98565beedbac54e51f35b7db`;
UI-only guidance followed at `e81b9dce28133861b5a8c5f45bb065e9721309f3`.
Deadline/saved-Node UX followed at `530f5d5c24d16887bc9ef28be5a14beab03e920a`,
then bounded automatic status at `854a5943285b413ebf6d133af3685dd7f300c929`.
The evidence driver now pins 67 reviewed normative/helper/Store/App/runtime
files and records all inputs separately. Latest Linux gates passed separate
84-event and two-event inventories on the same frozen dirty QA source. The
earlier Ubuntu 84-event receipt and all original FAIL receipts retain their
sources in the [validation record](native-app-validation.md#n3-idle-decay-and-automatic-status-follow-up).
The Hub-owned
[contract](hub-app-node-authority-contract.md) defines the protocol; this matrix
defines independent invariants.
Preparation or reuse of an existing N2/Client guard cannot count as N3 PASS.

The assets are the established Owner/account/Hub/App identities, each actual
grant instance, target Node identity/credential/generation, current epochs and
CAS versions, exact pending ciphertext, terminal operation/digest fences and
authenticated current observations. Adversaries may own another App/Node key,
replay an old valid packet, replace a preview or grant, race cancellation or
expiry against confirmation, lose replies, crash processes or deliver delayed
packets. Transport or UI availability is not authority. Host administrators
remain trusted; no stronger enclave/host compromise claim is introduced.

An existing account session and Root proof do not silently widen or renew the
N2 fifteen-minute lease. New authority must be explicit, finite and bound to
the reviewed instance/target. Every accepted request keeps its original grant
instance: later authority cannot retroactively legalize that request. A cached
receipt may describe past success but must not revive current permission.

Before the first N3 POST, including bootstrap status, the App must fetch
`/v2/owner/app-node/capabilities` and recognize the reviewed profile and limits.
Unsupported/404 means zero secret POSTs and zero new N3 pending operation.
The five account operations are prepare, complete, status, cancel and reconcile;
the INITIAL Client RPC allowlist is exactly `nodes.confirm`. `session.capabilities`
is not allowed. Node status uses its separate HTTP read permission and returns
only the selected Node. READ_EXISTING has an empty RPC allowlist and zero
confirmation budget. Both profiles bind the exact account-session ID/expiry,
not merely any live login for the same App. After session termination, a new
login may request a new explicit status-only instance, but cannot revive the
old grant or its pending packets.

A status read is not a durable mutation: a cached historical receipt or a signed
`READ_EXPIRED` for the exact read digest may settle only that read. A mutation
requires its original receipt or durable operation/digest fence, with atomic
Client counter handling; a counter gap/conflict must retain uncertainty.
Diagnostic caches have rolling bounds, not a lifetime polling quota.

The Store additionally requires the retained N2 Client session epoch **1**;
a later reset/restore epoch cannot be silently adopted into the first N3 grant.
`LoginRequired` describes a valid matching bound login, not whether a grant is
live: an expired/self-cancelled grant with the same live login has false, with
no operations/Node; an old session-ended instance under a new login has true.
Fresh authenticated terminal diagnostics must release an obsolete unconfirmed
preview so the user can explicitly start a safe new INITIAL instance.

An INITIAL instance that became ACTIVE but never confirmed any Node may be
abandoned: after authenticated expiry or self-cancellation, with no pending
operation and no local/server successful confirmation provenance, explicit
consent may create a new INITIAL instance from a valid pending candidate/code
and current head. The same still-valid unconfirmed candidate may be explicitly
selected again; its code is a selector, not authority. This cannot
renew N2, erase history or bypass security revocation. Once confirmation has
succeeded, only READ_EXISTING for the same exact binding is eligible. Acceptance
must include an abandoned/expired-before-confirm to new-code success case.

Node freshness is derived from an accepted bound relay heartbeat in
`machines.last_seen`, capped at 120 seconds. Relay-only heartbeat `{}` does not
make `machines.status` Worker-available. Empty, malformed, future or preapproval
heartbeat is UNKNOWN; fresh is CONNECTED and aged is STALE. V1 has no OFFLINE
shutdown signal. Repeated newer observation times never extend an old heartbeat.

The reviewed helper applies the size erratum: only the five N3 account
operations use a 384 KiB inner limit; default Client/N2 remains 256 KiB. Outer
384 KiB, body 192 KiB, original/receipt 128 KiB remain unchanged. Its producer
and integration review retain the real encrypted PQ outer-frame boundary tests
in the [Hub helper receipt](hub-app-node-authority-validation.md). These receipts
do not establish an independent production Hub/App/Node N3 result.

| ID | Boundary/fault | Independent acceptance oracle | Executed scope, 2026-10-17 |
| --- | --- | --- | --- |
| N3-01 | Trusted Hub and stable identities | Full pin/origin/account/Owner/App scope is checked before secret POST; preserve existing identities and keys | SCOPED_PASS — declared Linux process scope |
| N3-02 | Explicit instance authority | Account/password/public capabilities and expired N2 authority cannot create N3 permission; explicit consent binds the exact reviewed grant instance and allowlist | SCOPED_PASS — declared Linux process scope |
| N3-03 | Old packet versus renewed authority | Persisted old packet retains its original grant instance/digest; granting new authority never executes the old packet under the new grant | SCOPED_PASS — declared Linux process scope |
| N3-04 | Foreign scope/key/target | Real Hub independently rejects wrong Hub, Owner/account, App/device/instance, target Node/key/generation; do not count local constructor refusal as server rejection | SCOPED_PASS — declared Linux process scope |
| N3-05 | Existing Root and new signed consent | Reuse the exact already ACTIVE Root proved during N2, without a fresh KEM ceremony. Pending/unproved/revoked Root, missing/forged domain-separated ML-DSA consent, wrong signer or unauthorized purpose/scope leave authority unchanged | SCOPED_PASS — declared Linux process scope |
| N3-06 | Epoch/restore/revocation | Stale account/device/Node/grant epochs and restored-state receipts cannot authorize new execution or revive revoked state | SCOPED_TCP_EPOCH_REVOCATION; producer Store restore fence separately; full backup/restore NOT_RUN |
| N3-07 | CAS/preview substitution | Missing/stale version or changed target/candidate/digest is refused without consuming a valid preview or creating partial bindings/credentials | SCOPED_PASS — declared Linux process scope |
| N3-08 | Concurrent claim/confirm | Distinct candidates have one durable winner; identical exact retries recover the original result; another Owner/Node key cannot overwrite the winner | SCOPED_PASS — declared Linux process scope |
| N3-09 | Grant expiry | Real short valid windows expire over TCP; logical clock tests and actual long wall-clock waits are recorded separately | SCOPED short-intent wall expiry; full N3 lease wall expiry NOT_RUN |
| N3-10 | Revoke/expiry versus confirmation race | Current authority check and mutation commit share a transaction; each observed winner is consistent with one allowed ordering, with no partial effect or execution after a terminal fence | SCOPED cancel/confirm ordering; queued-expiry producer tests separate |
| N3-11 | Before-forward and after-commit loss | Fault traces distinguish an unsent original from a mutation actually committed before its response was lost; confirm effects from persisted production state | SCOPED_PASS — declared Linux process scope |
| N3-12 | Hub/App/Node crash windows | Actual owned child-process kills, disk reopen and exact request reuse preserve IDs/keys and one mutation; controller recreation alone is not process-crash evidence | SCOPED_PASS — declared Linux process scope |
| N3-13 | Absent original, fence, late delivery | An authenticated absence observation alone cannot clear uncertainty. Durable original operation/digest terminal fence precedes replacement; delayed original cannot commit after restart | SCOPED_PASS — declared Linux process scope |
| N3-14 | Duplicate/conflicting packet | Exact ciphertext recovers the exact durable receipt; same operation ID with changed ciphertext or reused nonce cannot replace it | SCOPED_PASS — declared Linux process scope |
| N3-15 | Unsigned/corrupt response | HTTP 403, timeout and corrupt PQ response retain pending uncertainty; only authenticated target-bound settlement permits progress | SCOPED_PASS — declared Linux process scope |
| N3-16 | Local persistence failure | Fail before network send; do not keep a memory-only replacement or regenerate identities after vault/disk failure | SCOPED_PASS — declared Linux process scope |
| N3-17 | Target Node status privacy | Return only the authorized target Node projection; no owner-wide goals, tasks, workers or unrelated Nodes leak into the status payload | SCOPED_PASS — declared Linux process scope |
| N3-18 | Genuine Node-only liveness | Installation, binding, credentials or a cached snapshot never imply online; only accepted current target Node heartbeats establish bounded Node freshness | SCOPED_PASS — declared Linux process scope |
| N3-19 | Cached-online decay | Heartbeat/as-of TTL governs display on failed reads and elapsed time alone; fetching/recovering an old response does not refresh its heartbeat time | Core/TCP SCOPED_PASS; portable Gio Router RED/GREEN; old Windows USER_REPORTED_FAIL, `1980dce` stop/restart stale/online USER_REPORTED_PASS; exact timing trace NOT_RUN |
| N3-20 | Node process/generation recovery | Restart/reconnect preserves approved Node identity; old credentials/generation cannot publish freshness or overwrite new status | SCOPED restart/revocation and real Node restart/heartbeat after App SELF_CANCEL; natural full N3 lease continuity and key rotation NOT_RUN |
| N3-21 | Honest Runtime/SSE boundaries | Node freshness is not an SSE live subscription or native Runtime availability/execution. Unrun Codex/native sessions remain unknown/NOT_RUN; no demo objects are rendered as live | SCOPED Node presentation; App SSE/native Runtime NOT_RUN |
| N3-22 | Target platform/user | Validate actual OS/arch, UID/nonroot and Codex version only on the disposable target fixture or explicit physical receipt; a bookworm Go builder does not prove Ubuntu target behavior | Earlier-source Ubuntu 24.04.4 container SCOPED_PASS; e426 physical Ubuntu initial binding/heartbeat USER_REPORTED_PARTIAL; latest 854 gates bookworm only; user-service/reboot/Codex execution NOT_RUN |
| N3-23 | Private evidence and cleanup | Real crypto/TCP/persistent stores; task-owned state, ports, caches and resources; hashes/safe facts only, no secrets or full private payloads; modules read-only; exact cleanup | SCOPED_PASS — declared Linux process scope |
| N3-24 | Windows/public/native Runtime | Independently attributable native Windows interaction, public HTTPS, physical Node and real native Runtime receipts required; Linux fixture results do not transfer | e426 historical PARTIAL/idle FAIL/manual stale PASS retained; `1980dce` Windows batch 1–5/8 USER_REPORTED_PASS, second-instance/Chinese USER_REPORTED_FAIL; dedicated native security/high-DPI, service reboot/full N3 lease continuity/Runtime NOT_RUN |
| N3-25 | Abandoned INITIAL and explicit read authority after expiry | Before any successful confirmation, authenticated terminal/no-pending state permits a new explicit INITIAL code/grant/head; after confirmation and consumed code, explicit Owner consent may create a new finite status-only instance for the same exact approved Node/binding, with current head CAS and zero confirmation budget; no re-pair, key upgrade or N2 renewal | SCOPED self-cancel/session replacement; full N3 lease wall expiry NOT_RUN |
| N3-26 | Read-only renewal cannot authorize mutation | Old packets cannot borrow the new read grant; that grant cannot confirm; changed Node/binding/key/generation is rejected, and cached online state still follows the original heartbeat rather than a new poll's observation time | SCOPED_PASS — declared Linux process scope |
| N3-27 | Automatic selected-Node status | Lock-held exact scope/full binding/live permission checks precede new durable ciphertext; only status reads; wrong target/expiry skip without write; uncertain response freezes later ticks/restart; signed terminal settles; manual recovery precedes new reads | Separate actual Core/TCP 2/0/0 SCOPED_PASS; portable coordinator tests separate; Windows automatic stale/online USER_REPORTED_PASS, exact 30-second cadence and fault traces NOT_RUN |

The original cases below run in the full 84-event selector. The earlier Ubuntu
receipt and latest Linux receipts retain their independent source attribution;
the two automatic-entry cases use a separate selector and were not run by the
earlier Ubuntu gate. Exact names/subcases are in each result's `expected_tests`.
Zero matching cases, missing prerequisites, skips, unknown outcomes and
harness-only success never establish N3 acceptance. N2/Windows history and
earlier failures retain their tested source attribution.

| Matrix rows | Actual independent cases (`TestN3` prefix) |
| --- | --- |
| 01–02, 05 | `ActualAppUnsupportedCapabilitiesSendNoSecrets`, `ActualIdentityFlowAfterWallClockN2Expiry`, `ActualAppConsentBindingRelayAndWallClockDecay` |
| 03, 25–26 | `OriginalInstanceCannotBorrowNewInitialOrReadGrant`, `ActualAppSelfCancelRequiresExplicitReadOnlyConsent`, `ActualUnconfirmedSessionReplacementAllowsNewInitial` |
| 04–07, 09 | `ServerRejectsIndependentProofScopeAttacks`, `ServerRejectsForgedCompletionPreservingPreview`, `RealPersistedEpochAndRootSessionFences` |
| 08, 14 | `ConcurrentPrepareConfirmAndConflictingReplay` |
| 10 | `RealConfirmationVersusCancellationOrders` |
| 11–15 | `ActualAppExactFaultRecoveryAndLateOriginal` (five operations × six faults), `ActualConfirmationLocalCommitCrashBoundaries` (three local CAS windows) |
| 13–14 | `ReadCacheRollingBoundsAndPermanentMutationRecovery` |
| 16 | `ActualVaultFailureStopsBeforeSecretSend` |
| 17 | `StatusContainsOnlyExactSelectedNode` |
| 18–21 | `ActualImmediateRelayHeartbeatRetainsSubsecondOrder`, `ActualAppConsentBindingRelayAndWallClockDecay`, `RevokedNodeCannotPublishOrReuseReadProvenance` |
| 22–23 | Driver-recorded runner OS/arch, explicit UID 1000, image/binary/source hashes, isolation and owned-resource cleanup |
| 20, 27 | `ActualAutomaticStatusKeepsScopeAndSelfCancelledNode`, `ActualAutomaticStatusLossFreezesTicksUntilExactRecovery` — separate `--auto-status-only` selector, two events |

N3-05's inactive/unproved-human and missing-N2-history checks additionally use
the separately attributed producer Store case
`TestN3StoreMissingCompletedN2AndInactiveHumanDenyAuthorityKeepDiagnostics`.
For N3-06, independent TCP cases mutate only stopped private DB epoch or
revocation rows and restart the actual Hub. The producer's
`TestN3StoreRestoreAndSecurityRevocationPreserveIdentityCountersAndHistory`
separately checks the Store restore fence and historical receipt. A full
backup/restore campaign is **NOT_RUN**. N3-09 proves actual short intent expiry;
natural full 15-minute N3 lease expiry remains **NOT_RUN**. The old N2 lease did
expire naturally in both final runs. N3-10 checks actual cancel/confirm ordering;
the producer's transaction-time tests separately cover expiry while queued.
N3-20 covers retained INITIAL recovery and revoked credentials/bindings;
Node key rotation/UPGRADE remains outside the slice. The rolling cache's
five-minute age is an explicitly controlled persisted fixture, not a wall wait.

The 84-event Core actor queries `Controller.Snapshot()` after its real wait;
it does not prove native no-input redraw. Latest automatic-entry tests invoke
the production flagged refresh through the actual App child, not a simulated
client. Their triggers are explicit test commands, not a real Windows timer.
They separately prove UNKNOWN-to-real-heartbeat status, unchanged read grant,
counter/budget and keys, no-write wrong-target/logical-expiry rejection,
SELF_CANCEL Node continuity, manual READ_EXISTING consent, server-signed
revocation settlement, and loss/restart/multi-trigger freeze followed by exact
manual recovery and fresh reads. The later `1980dce` Windows batch reports
automatic stale/online behavior and account-session expiry hiding; full natural
N3 grant expiry/Node continuity and precise Windows clock/event-loop traces
remain NOT_RUN.

The supplied Ubuntu 24.04.3 / x86_64 / UID 1000 / `codex --version` 0.163.0
output is **USER_REPORTED_ENVIRONMENT**. That original environment output alone
did not establish an installed/approved Node or native Runtime execution. Later
`e426` user-reported initial binding/heartbeat and Root's read-only process/binding
observations are recorded separately; they do not accept the new Windows build
or full Node service/reboot/lease continuity. Repeated status polling must
not extend an old heartbeat's freshness merely by receiving a newer ObservedAt.

## Login-first presentation safety matrix

Prepared from `5fee32c` on 2026-10-17; independently reviewed implementation
`1980dced7c20da0be40ac8a03892a911d2ffab9b`. This is the presentation change for an
existing trusted configuration before account login. It does not introduce a
new account system, require password entry on every launch, or replace existing
first-connection/Owner setup. A restored session may reveal the workspace only
after this process completes trusted profile recovery and a fresh authenticated
server inspection. Cached profile metadata, Root ACTIVE and a saved Node binding
alone do not establish login.

The Core's current SESSION_ACTIVE, OWNER_READY and OWNER_PROOF_PENDING account
states may qualify with a verified Hub and an explicit future session deadline.
OWNER_PROOF_PENDING must remain usable after account authentication; login does
not activate Root or widen Node/Manager authority. SESSION_RECHECK_REQUIRED,
LOGIN_REQUIRED, missing/malformed/expired deadline and an unverified Hub stay
behind the presentation gate. Account recovery retains priority. A Node-only
uncertain read does not itself end an otherwise verified account session.

App owns the implementation and UI tests. QA independently reviewed the actual
root layout, privacy predicate, input transitions and recovery reachability.
App's final portable normal/race runs each passed 141/0/0, with Linux/Windows
vet and Windows cross-build exit 0. These are **SOURCE_REVIEW / PORTABLE_PASS**,
not native Windows execution or visual acceptance. See the
[source-bound receipts](native-app-validation.md#login-first-presentation-follow-up).
Existing 84-event and automatic-entry two-event receipts retain their tested
source. No Hub/Node deployment or key change is part of this work.

| ID | Boundary | Required oracle | State |
| --- | --- | --- | --- |
| LOGIN-01 | Existing configuration, not logged in | Root layout exposes only the login form and necessary neutral entry/recovery controls; no status card, stored account/Owner/Node values, fingerprints, grant deadlines, canvas or preview | SOURCE_REVIEW + PORTABLE_PASS; basic signed-out screen USER_REPORTED_PASS |
| LOGIN-02 | Cached or untrusted session | SESSION_RECHECK/expired/malformed/no session or unverified Hub never reveals details, even with cached Root ACTIVE, Node online, bound Node or stored receipts | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-03 | Current account authentication | Freshly verified SESSION_ACTIVE/OWNER_READY/OWNER_PROOF_PENDING may reveal the workspace; Root pending remains pending and available actions are unchanged | SOURCE_REVIEW + PORTABLE_PASS; original-account login restoring the same Node USER_REPORTED_PASS |
| LOGIN-04 | Input privacy | Stored username is not prefilled; password stays masked and is cleared on submit, login/authentication loss and full scope change. Clearing is transition-based so typing is not erased every frame | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-05 | Hidden sections and stale input | Details, fingerprint expansion, preview/canvas and old profile identity widgets cannot leak through an alternate branch or dispatch hidden management/Node actions before login | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-06 | Multiple profiles and routing | Prelogin selection uses neutral labels bound to exact trusted profile IDs; never silently pick another account/Hub from a username. Credentials are sent only through the existing verified origin/pin flow | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-07 | Recovery without identity disclosure | Account Recover/Retry and, where required, saved Node recovery remain reachable with neutral copy; retain original IDs/ciphertext/receipts and priority. An unauthenticated screen does not display Node identity to explain recovery | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-08 | Necessary first connection | No-profile/unfinished setup can still reach the existing controlled connection, exact Owner import/proof and activation flow; the login view neither fabricates a Hub nor generates new keys or authority | SOURCE_REVIEW + PORTABLE_PASS |
| LOGIN-09 | Logout, expiry and scope transition | Hide old workspace information when account authentication is lost/rechecked or scope changes; clear stale input/expansion state, while preserving encrypted profiles, keys, Node bindings and pending recovery | SOURCE_REVIEW + PORTABLE_PASS; logout/account-session expiry hiding USER_REPORTED_PASS; scope-transition physical cases unverified |
| LOGIN-10 | Automation and authority | The presentation gate grants nothing and does not mutate AvailableActions. A hidden screen pauses future Node ticks and reopening starts a fresh interval without discarding an in-flight packet. Existing guards still require current exact permission; ordinary Node pending with valid account login retains its separate busy/recovery semantics | SOURCE_REVIEW + PORTABLE_PASS |

`TestAccountInformationRequiresCurrentTrustedSession` covers LOGIN-02/03;
`TestPreLoginPresentationHidesIdentityButPreservesGenericRecovery` covers the
projection, original action/profile locator preservation and recovery ordering
in LOGIN-01/05/06/07. `TestLoginRestoresOriginalBindingAndFirstSetupStillHasItsOwnFlow`
covers LOGIN-08/09, and `TestPresentationInputResetUsesFullScopeAndAuthenticationEdge`
covers LOGIN-04/06/09. `TestNativeAccountScreenPauseRestartsIntervalWithoutDroppingPending`
covers LOGIN-10's coordinator behavior. The root layout branches, widget reset,
credential dispatch and unchanged Core guards were reviewed separately; these
portable tests do not execute the Windows root renderer, vault or TCP recovery.

On 2026-10-17 the user reported that the three basic Windows 11 steps matched
expectations: signed-out pure login, original-account login restoring the same
GPU1 Node, then logout hiding the information. This is **USER_REPORTED_PASS**
for the clean `1980dce` delivery candidate, SHA-256
`27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`;
see the [dated observation](native-app-validation.md#login-first-presentation-follow-up).
It is not independent native execution or complete Windows acceptance. The
later [eight-step user batch](native-app-validation.md#windows-11-eight-step-user-batch)
also reports steps 1–5/8 passing: wrong-password/correct-login path, reopen,
automatic stale/online, self-cancellation, explicit same-Node read access and
account-session natural expiry/relogin. The optional recovery branch in step 1
was not reported separately. Step 6's second-instance first-setup/device-code
entry is USER_REPORTED_FAIL; step 7's Chinese text is USER_REPORTED_FAIL, with
other layout/input subcases not individually reported. The App owner handles
the entry defect; the user deferred font/style work. Dedicated DPAPI/ACL,
high-DPI, full uncertain-result recovery and independent native tests remain
NOT_RUN. The prior three-step record and old 84+2 receipts retain their source.

The follow-up [profile-recovery source](native-app-validation.md#profile-recovery-follow-up)
is `84d7aee`: native startup requires complete trusted discovery before first
setup; busy/failed recovery exposes only retry/trusted-resume controls and
rejects other Core actions. Snapshot reset publishes those controls atomically.
Conditional identity persistence preserves an unchanged vault during recovery;
new/missing identities and the original request still persist before POST.
Producer normal 290/0/0, scoped Core race 21/0/0, UI/native race 149/0/0, Root
native 369/0/0 and disposable interop passed. This is a scoped source/portable
fix, with matching Windows two-instance/retry execution NOT_RUN. The old
candidate's USER_REPORTED_FAIL and deferred Chinese display failure remain.

## Same-Node real Codex Thread acceptance preparation

Preparation baseline `a14ad28`, 2026-10-17. The user's next priority is an actual
question/answer between two independent real Codex Threads on the same logical
Node ID and physical gpu1 host, through the existing production Join/Fabric/MCP
chain. New workspace/task contracts and task creation are paused. The user
will personally execute the real gpu1 two-Thread acceptance. This supersedes
the earlier Root-run Runtime proposal: Root/QA must not arm the WS adapter,
create SIDs, seed/continue model turns or operate the native queue. Existing
synthetic fixtures and archived WS work are retained separately. No real
pair, model turn or new peer authority has been created by this preparation.

This main lane targets the existing public Hub/account plus the actual gpu1
Node. A disposable real-Runtime lane, deterministic protocol tests and recording
fixtures must be labelled separately; none replaces the requested public lane.
The existing `test-two-node-codex-native.py` creates two independent Node/container
namespaces and is not a same-Node gate. Its old source, images and results stay
attributed to that distinct topology.

Current source has a trusted local Join bridge in the relay-only Node, but the
Hub Nodes wrapper only exposes its reviewed route allowlist. The underlying
Fabric service exists; the missing general Join/metadata/key-consent routes
must be reviewed by Hub, along with the typed Owner authorization path. An App
account login or existing N3 status grant does not supply those permissions.
Owner private keys remain in the existing vault; preparation does not export
them or widen the old status grant.

The [same-Node relay implementation](same-node-group-relay.md) sends new ordinary
same-Group ASK/REPLY through sealed HubRelay. Generic native direct eligibility
remains guarded by the [direct design](native-local-direct-design.md): same
Node/host labels alone do not establish the same authenticated Codex account
or a usable exact-Thread native API. A legitimate Relay fallback may satisfy
the conversation lane with its actual route recorded. It is not direct PASS.

| ID | Boundary | Required oracle | State |
| --- | --- | --- | --- |
| N3-TT-01 | Exact deployed topology | Pin public Hub origin/identity and actual Hub/Node/Codex artifacts; both native SIDs are distinct on the same real gpu1 host and one approved logical Node/binding, not two fixture Nodes | NOT_RUN; PRECONDITIONS_PENDING |
| N3-TT-02 | Explicit native Join | Use a real selected Network and two reviewed slots. Each trusted Runtime connection joins its original SID with zero peer/directory authority to its own stable Endpoint/current native SessionBinding; caller JSON cannot impersonate another SID/Node | NOT_RUN |
| N3-TT-03 | Unjoined isolation | Before Join, peer directory/resolve/receive cannot enumerate joined Threads or recover peer content. Node enrollment, account login and another Thread's membership confer no visibility | NOT_RUN |
| N3-TT-04 | Explicit authority and keys | Current Group/member/binding/lease and exact Endpoint key candidates/Owner grants authorize only the selected conversation; no implicit Join, directory/history grant or broad status-grant upgrade | NOT_RUN; PRECONDITIONS_PENDING |
| N3-TT-05 | Original context and B-only answer | Record separate private context witnesses and a fresh random B-only answer before traffic; A receives the question but never the answer in its prompt/config. Restrict/audit alternate file/shell/history/oracle access so A obtains the answer only through the correlated peer REPLY; Root/script never forwards peer bodies | NOT_RUN |
| N3-TT-06 | Actual native tool use | Each real Thread completes the production MCP calls on its original SID. Recording queues, curl/SDK calls by the driver and script-injected answers cannot stand in for model consumption | NOT_RUN |
| N3-TT-07 | ASK/REPLY correlation | A's ASK has exact target/operation/request/message identity; B receives that request and replies to its original request ID; A receives the matching answer and independently retains its original context witness | NOT_RUN |
| N3-TT-08 | Separate completion levels | Record transport acceptance, queue/injection observation, actual B consumption, correlated REPLY, actual A consumption and completed native turns separately; no earlier level implies the next | NOT_RUN |
| N3-TT-09 | Honest route | Record trusted route evidence for each message. Sealed HubRelay fallback is explicit; direct requires separate host/account/API/Guard evidence and is never inferred from equal Node IDs | NOT_RUN; DIRECT_UNACCEPTED |
| N3-TT-10 | Negative scope and revocation | Wrong Group/Endpoint/native binding, stale lease/epoch and revocation of owned acceptance membership/grants deny further traffic; another active scope cannot rescue it | NOT_RUN |
| N3-TT-11 | Loss/restart/replay | Recover original operation/ciphertext and durable request history after loss/restart; do not reseal or reinject an uncertain native write, and do not label queued data as consumed | NOT_RUN |
| N3-TT-12 | Reply/cancel ownership | Only the original receiver can reply and original sender cancel; cancel acknowledgement does not prove the Runtime stopped or that an uncertain question was never consumed | NOT_RUN |
| N3-TT-13 | Privacy and bounded execution | Use owned synthetic question/answer markers, bounded turns/time/budget and private traces; publish hashes/counters only, omit credentials/keys/full native context, and distinguish turn counts from provider-request counts | NOT_RUN |
| N3-TT-14 | Safe restoration and cleanup | Owned Group/Thread grants, helpers and artifacts have explicit cleanup; preserve the real Node/account/Owner keys/binding and unrelated Threads. Rejoining/recovery requires current authority and preserves original SID/context evidence | NOT_RUN |
| N3-TT-15 | Separate authority lifetimes | Protected new App authorizations require its current account session. Account-session expiry does not itself revoke established peer grants; N3 status-access expiry/cancellation neither grants nor revokes peer authority. Native SessionBinding/lease, Group/member/grant and Node/Owner revocation remain independently authoritative | NOT_RUN; CONTRACT_REVIEW_PENDING |
| N3-TT-16 | Crypto epochs, budget and replay | Separate App session epoch, native binding epoch, E2EE key/counter/replay state and message budgets. Approved `native-pair-v1` fixes four independent ASK roots in either direction, at most one outstanding ASK, one reply per ASK/four replies/eight messages/eight native deliveries, 8 KiB plaintext per message and 64 KiB total plaintext, 128 KiB ciphertext per message and 1 MiB total ciphertext. Exact retries cannot reset/double-charge budget or revive permission | CONTRACT_DEFINED; full real acceptance NOT_RUN |
| N3-TT-17 | Lightweight, measured operation | Reuse existing Go/crypto/transport/persistence with no new coordination service/dependency. Record actual request/response JSON bytes, peer ciphertext bytes, latency, requests/retries/native submissions, owned-SID model calls and idle pair traffic separately; no extra authorization renewal, model loop or polling is inferred from availability | NOT_RUN |

The following is a **manual acceptance skeleton after delivery**, not a set of
currently executable pair commands. At 2026-10-17 13:57 UTC, independent public
HTTPS GETs still show clean Hub `e42640d`, old App/Node capabilities available,
and new native-pair capabilities HTTP 404. The delivered Windows App remains
`1980dce`, SHA-256
`27aa167c847f278b26e7a2e908f7baab4e6eec7971b10b32f0b4f7a72ccb4b28`;
it has no pair UI/Dispatch. The `84d7aee` profile fix and new pair WIP are not a
new user-delivered package. Current executable manual scope remains normal
account login and the original gpu1 Node status. Pair Join/authorization/dialogue
steps below are **NOT_RUN / DELIVERY_PENDING**.

1. **Verify the delivered upgrade.** Root supplies actual reviewed Hub/Node/App
   revisions, source/image fingerprints, Windows executable SHA-256 and real
   entry names. The user checks the executable with PowerShell
   `Get-FileHash -LiteralPath '<delivered EXE path>' -Algorithm SHA256` and
   compares the release manifest. This is a checksum template, not a delivered
   filename. Preserve the original account, vault, Owner/device keys, Node ID
   and bindings. A cross-build alone is not Windows GUI/DPAPI/ACL acceptance.
   Root's read-only installed Codex 0.163.0 `mcp list --json` currently returns
   `[]`: Cicada MCP registration/loading is another delivery prerequisite.
   Supply reviewed configuration limited to these two Thread launches, preserving
   global tools/model/config. Check Cicada MCP actually loaded in **each** Thread;
   a global listing or a present executable is not that proof. Do not run a
   persistent global `codex mcp add` as an inferred setup action.
2. **Prepare two empty slots in the App.** The user logs in normally, selects
   the original gpu1 Node and uses the delivered new pair authorization entry.
   Review the existing Owner/Node pins, private Group and bounded policy before
   approving bootstrap. Login/status access alone supplies no Root/pair right.
   No native SID or peer permission is inferred from the two empty slots.
3. **Join the user's two actual Threads on the same Node.** The user personally
   selects/opens A and B, retains both original SIDs and distinct private context
   witnesses, and gives a fresh at-least-128-bit answer only to B. In each
   original Thread, use the delivered reserved-slot Join entry for its own slot.
   Both launches use the actual approved `CICADA_MACHINE_ID=gpu1-node` and the
   original `CICADA_NODE_STATE_DIR`, not a fresh Node directory. Native SID is
   injected by Codex and verified against its local session/workspace record;
   never set a literal `CODEX_THREAD_ID`/`CODEX_SESSION_ID` to impersonate A/B.
   Root supplies the exact Cicada executable/API origin, original Hub/Owner pins
   and scoped MCP session-state location after the new Node entry is reviewed.
   No default localhost API, manually supplied session token or guessed new
   flags/tool fields can fill that gap. MCP session persistence remains private
   and scoped by origin/harness/native SID/Node; registration grants no rights.
   Root will add exact tool/CLI syntax after implementation; generic old Join,
   a guessed command, a second Node or an operator DB grant is not a substitute.
4. **Authorize the actual pair in the App.** Review both distinct actual SIDs,
   the same Node/Network/Group, candidates and expiry; approve each slot's exact
   consent. Empty slots and the first consent leave peer traffic denied. Only
   the compatible second consent may activate both. The Owner key stays in the
   original App vault. The App does not carry peer questions or answers.
5. **A asks, B answers, A receives.** The user tells original A to make one
   production `cicada_ask` to B. B receives it in its original context and uses
   `cicada_reply` for that exact request ID, from the answer it already knows.
   Both B and A receive through the guarded delivery path confirmed for the
   delivered build, each in its original context; A reports the correlated
   answer plus its own witness. The exact delivery/receipt entry point remains
   DELIVERY_PENDING. This Pair tool contract is limited to ASK/Reply/status/cancel;
   no receive-tool invocation is prescribed here. The ASK/Reply names are usable
   only after the new chain is delivered and authorized. If the user must
   explicitly continue B/A at a safe point, label USER_CONTROLLED_SAME_SID;
   do not claim automatic loaded/cold
   wake. Neither the user nor Root/scripts pastes the peer body/answer into the
   other Thread. The first check uses one ASK/Reply, preserving remaining budget.
6. **Record results and optional same-pair reopen.** Record exact executable,
   Hub/Node versions, original SIDs, request/message IDs, actual tools, route,
   answer/witness digests and completion levels. No keys/tokens/full private
   context go into public evidence. Equal Node labels are insufficient; record
   trusted Node/binding evidence. Sealed Relay is recorded as SEALED_RELAY.
   Retain original SIDs/context for a later manual reopen/second exchange. User
   observations are USER_REPORTED until independently backed by matching traces;
   absent traces and unexecuted Windows checks remain NOT_RUN/NOT_PROVEN.

The delivery gaps include per-Thread Cicada MCP configuration/loading, the guarded Hub setup/peer surface, trusted Node reserved
Join/candidate/Owner-pin/policy enforcement, and the delivered Windows App's
original-vault pair review/consent/reconcile flow. Missing routes, grants or UI
stop the manual procedure; there is no raw SQL, broad Client grant or old Hub
fallback. No deployment operation is authorized by this skeleton. Keep destructive
loss/restart, budget exhaustion and revocation adversaries in the isolated
protocol fixture. A revoke receipt cannot undo already consumed native work.

Fault coverage includes pre-forward/post-commit loss, corrupt/unsigned reply,
duplicate ASK/REPLY, delayed original after cancellation, binding/lease change,
and queue/injection crash windows. Fixture-only outcomes remain separate from
actual public native consumption. Retain request/result hashes, process/turn
and tool counts, source/image/CLI hashes, route evidence, exit code, cleanup and
all incomplete levels. No real two-Thread conversation has passed this matrix.
Use existing transport/driver counters and bounded private traces for these
measurements; do not add a monitoring framework or a separate optimization
project before the usable chain closes. Distinguish application JSON size from
TLS/socket bytes and permission/message budgets from provider cost. Idle
observations cover only the owned pair/SIDs, so unrelated development activity
and the resident Node's existing heartbeat/SSE do not become claimed pair work.

The independent protocol lane is executable with
`bash scripts/test-native-pair.sh`. It builds the actual CLI and acceptance
binary in the pinned disposable offline Docker image, then uses the existing
production App N2/N3 flow to approve one synthetic Node before the new PQ
caller attempts bootstrap. Its initial five cases cover exact bootstrap replay
after Hub restart, a genuine Owner signature over the wrong Node scope, missing
Owner proof, pre-forward prepare loss and post-commit complete loss with exact
reconciliation. They do not create Codex SIDs or model turns. Node reserved-slot
Join, both zero-permission candidates, dual consent and actual native/MCP traffic
will extend this lane when their typed production surfaces are available.
The first execution reached real capabilities HTTP 404 after all five actual
N2/N3 setups and returned exit 1, **EXPECTED_RED_SERVICE_UNAVAILABLE**. No new
pair secret POST or business/fault assertion executed; see the validation record.

Root's separate standard disposable Client compatibility gate on clean
`209b208` passed, exit 0, with four actual TCP protocol/client/Owner-bootstrap/
recovery cases. QA checked its source/artifact attribution and independently
confirmed the five owned resources and scratch absent. This is clean-source
compatibility evidence alongside the App producer's earlier dirty-`17da393`
Core/UI results; it does not enable the false Pair capability, settle the new
Hub read-cache defect or execute the user-only native/Windows/public lane.
Full receipts and hashes are retained in the existing validation record.
