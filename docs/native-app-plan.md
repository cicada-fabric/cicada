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
| N3 — Authorized live canvas and Node actions | Add live objects only from an authenticated, authorized Hub/Node read path; add explicit guarded Node actions and status reconciliation. Empty/unavailable canvas stays empty; no demo objects are presented as live state. | Not implemented. Requires server-side read/action authorization and durable operation semantics. |
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
