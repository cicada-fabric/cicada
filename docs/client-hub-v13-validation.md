# Client / Hub v1.3 frozen validation

Frozen candidate gate: **PASS** (2026-09-27). The Hub/Node/Control source is clean;
the disposable TCP gate used the exact local image below. This record is excluded
from the exported bundle file list so its own digest cannot recursively affect it.

| Artifact | Frozen identity |
|---|---|
| CICADA source | `be0269e80c41e94881d131bd4f4b233e80b6ffe6`; fingerprint `f21f206525c9deb6f959988d675606257ee796ae39f46b973f9bdd714cda7e4e` |
| Contract | `client-hub-v1.3`, wire v1, 33 operations; catalog SHA-256 `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Protocol bundle | `.cicada-data/contracts/monitor-v13-be0269e/client-hub-68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9.tar.gz`; SHA-256 `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9` |
| Hub image | Local tag `cicada:client-hub-v1.3-be0269e-validated`; image ID `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783`; not pushed to a registry |

`python3 scripts/client-contract.py verify <bundle-path>` verifies the exported
bundle manifest and contents. The candidate catalog check and seven contract /
recovery Python tests passed. Full `go test -count=1 -timeout 15m ./...` plus
`go vet ./...` passed; after the Confirm projection and inactive-Group review fixes,
the affected Control and Server package tests/vet and focused races passed. Five
Store Monitor concurrency/recovery race tests passed. The encrypted Monitor TCP
lifecycle tests passed.

Disposable Hub smoke and recovery tests used real TCP and exited 0. Result:
`.cicada-data/client-v13-be0269e/interop/result.json`. Idle measurement for this
same image is `.cicada-data/client-v13-be0269e/validated-footprint/idle-hub-20260927T004929Z-902ed543.json`:
RSS was 27,226,112 → 27,291,648 → 27,291,648 bytes (about 26 MiB), under 128 MiB
and 0.5 CPU limits. PID ticks were 30 → 30 → 31 → 31 over 7.695 seconds; 10 ms
resolution does not support a long-term CPU or load-capacity claim. The earlier
`eb056` image/tag was removed and is not evidence for this delivery image.

At the frozen gate, Android v1.3, real native Monitor delivery, dual-physical-Node
and public HTTPS checks were **NOT_RUN**. A later scoped real native Monitor
acceptance **PASS** is recorded in [the native validation record](architecture-v2-native-validation.md);
it used three real Codex Threads on two logical Nodes in one test container with
controlled safe-point resume. It does not establish Android interoperability,
dual-physical-Node operation or unattended cold wake. The later Client emulator
acceptance below is a separate run and does not combine with native delivery.
The frozen Hub gate remains separate evidence and does not itself claim native
Monitor consumption or Android interoperability.
The v1.2.1 Android PASS remains evidence only for its own historical source and image.

## Client-reported Android emulator slice (Core review complete)

The Client reported a limited v1.3 Android emulator **PASS**. Core completed a
read-only code and evidence review; it did not rerun the Android tests. Evidence
references: implementation `9568b2ff6d4e156b70484c10b7fd5195405004b0`,
report `3123cfc463e1e8bca025551d5fb6355670375751`, and app APK SHA-256
`f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700`
([Client validation report](../../CICADA_CLIENT/docs/client-hub-v1.3-be0269e-validation.md)).
The Client reports 21 Kotlin and 13 JavaScript tests passing. Its fixed-Hub
interoperability checks recovered lost true-HTTP-200 Prepare and Confirm
responses by replaying the exact original packets, and rejected Confirm after
broadcast permission revocation (`MONITOR_PREVIEW_REFRESH_FAILED`,
`confirmAttempted=false`). The real React Native UI reached `APPROVED` with an
empty recipient ledger. The run used synthetic authorization Endpoints; this
empty ledger does not establish recipient delivery or model consumption. The
separate native PASS above does not make this a joint Android-to-native E2E.

The later fixed-Hub Android/native joint attempt **FAILED** during authenticated
heartbeat after stale-presence cleanup marked leased Endpoints offline. The six
Android setup selectors passed, but Owner Group authorization and positive
Prepare/Confirm, dispatch and recipient consumption were not reached; see the
[joint acceptance record](client-monitor-native-joint-validation.md). This does
not change the separate standalone native PASS.
The post-freeze `148c0ef` stale-presence fix and regression gates are recorded
there; they do not alter this frozen Hub image or establish a corrected native
run.

The [fixed-Hub Android Monitor Prepare recovery record](client-monitor-v13-recovery-fixture.md)
now links the Client's 2026-09-27 [recovery-fault report](../../CICADA_CLIENT/docs/client-monitor-v13-recovery-faults.md).
On clean Client tree `de139c9`, Core review at `5357e2a` confirmed **PASS** for
three fresh fixed-image Hubs and 12/12 Android JUnit selectors. This was strictly
outer RPC recovery-ledger and original-packet-retention coverage; the Monitor
Prepare business handler, Confirm, native delivery and model consumption did
not run. Physical Android, dual-physical-Node operation and public HTTPS remain
**NOT_RUN**, and unattended cold wake remains **UNSUPPORTED**.

## Consent and expiry semantics

Per-recipient outcome rows are seeded at `DISPATCH_AUTHORIZED`; `PREPARED` and
`APPROVED` may therefore have an empty `recipients` list. Only
`DISPATCH_AUTHORIZED` requires the full fixed snapshot count. An empty list is not
evidence of delivery.

The five-minute Hub preview expiry and each Owner Group key-grant expiry are
independent; a grant need not cover the full preview. Confirm and dispatch rerun
current authorization through `currentUserMonitorSnapshotTx` →
`buildSameGroupBroadcastV2SnapshotTx` → `readSameGroupSealedV1EndpointTx` →
`evaluateGroupEndpointKeyGrant` for the source and every recipient. Read-only
recovery may return a previously signed response, but that is not current
authorization; do not automatically re-prepare, renew or re-sign.

Android's local +5-second allowance only tolerates clock skew in the upper bound
for a future preview TTL. It does not alter signed/serialized `expires_at`, extend
the Hub's five-minute TTL or extend OwnerProof expiry; it adds no wire field or
enum. `TestUserMonitorConsentShortOwnerGrantExpiresBeforePreviewAndRevalidationDenies`
covers an approved preview outliving a shorter grant and denial on current
revalidation. `go test ./internal/store -run '^TestUserMonitorConsent' -count=1`
passed in Go 1.27.1 Docker (exit 0, 4.433s); this is Store-only coverage, not TCP
HTTP or Android interop. Frozen Hub, image, catalog and bundle pins are unchanged;
the limited Client-reported Android PASS is recorded above.
