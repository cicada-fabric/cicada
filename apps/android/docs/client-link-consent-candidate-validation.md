# Link consent candidate validation

## Result and release boundary

The offline candidate implementation and focused validation are complete. The
five operations remain closed:

```text
link.key_manifest
link.key_grants
link.key_grant
link.review_policy_preview
link.review_policy_grant
```

`LINK_CONSENT_READY` remains `false`, `LINK_CONSENT_RELEASE` remains `null`, and
the production operation count remains 39 implemented / 16 closed. No new
operation is admitted by a public catalog or encrypted capability alone.
Android runtime pins remain `client-hub-v1.6.1` and catalog
`6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b`. There
has been no v1.6.3 runtime repin, consent RPC activation, or candidate APK
build.

Core's clean v1.6.3 contracts have since been imported at
`contracts/client-hub-v1.6.3-e8a029d/`. Root's clean-contract import receipt is
SHA-256
`3fad7774e29c286a11c2a706dbd5498c7274a17be41d6aa0fb591b0865770dff`. Its
manifest binds source revision `e8a029d79bbdddb75ea376afa76e62a5c8444f59`,
wire version 1, schema 55, 55 operations, and catalog SHA-256
`5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`. This
establishes clean source provenance for the imported contract and vector; the
manifest reports Android interoperability and native runtime as `NOT_RUN`.
The import does not replace the accepted v1.6.1 runtime baseline or itself
accept Android compatibility.

The imported public synthetic vector
`contracts/client-hub-v1.6.3-e8a029d/cicada-go/internal/e2ee/testdata/link-client-proof-v2.json`
is 166,223 bytes, SHA-256
`aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d`, and is
byte-identical to the Android test asset. It contains public identities,
signatures, signed bytes and complete Link/Endpoint proof data, but no private
key or deployment credential. The Kotlin host tests independently verified
this fixture and its tamper cases. The fixed vector time is test data, not a
production clock or authorization source.

## Candidate behavior

The TypeScript module validates only the pinned v1.6.1 request and response
shapes. It rejects unknown candidate-only retained-evidence fields. Key-grant
status metadata is explicitly `UNVERIFIED`; `accepted: true` does not imply
bilateral cryptographic verification. The pure review model captures full
manifest and scope inputs, requires a one-use explicit review and fresh scope
comparison, but cannot release consent. Its packet-recovery model is offline
and ephemeral; it does not claim native authentication or durable custody.

The pure Kotlin verifier reuses the existing Endpoint proof and wire-crypto
helpers. It validates canonical Link contract and manifest bytes, both complete
Endpoint ML-DSA attestations, and both OwnerLinkKeyGrant proofs against caller
supplied current Link/Endpoint and Owner-key authority. The v1.6.3 retained
proof DTO verifier remains candidate-only. A successful verification proves
current consent evidence, not Link routing, Node authorization, peer message
delivery, Runtime injection, or model consumption.

## Remaining native integration inputs

The clean Core v1.6.3 encrypted `link.key_manifest` response is the
server-authoritative, single-transaction snapshot for both current Link sides.
It contains the current Link contract and `scope_snapshot` revisions together
with both Endpoint candidates, bindings and attestations. A second
`topology.snapshot` or `link.list` read is not required to acquire those
cross-Owner authority fields. The bare manifest JSON is not a trust anchor,
however: a future native method must bind it to the authenticated encrypted RPC
result and the captured Hub profile, authenticated Owner, device, session epoch,
Link ID and version. It must build the verifier's caller-bound
`CurrentLinkAuthority` from that fresh server response, verify the canonical
contract and both Endpoint proofs, and fetch and verify the authority again
before any consent write. User-supplied or unbound candidate JSON cannot fill
that role. Android does not yet have this dedicated native Link method; the
five operations remain closed.

The local enrollment trust record contains the full independently entered
Owner public identity, but not a current key state/version. The fresh v1.6.3
`link.key_grants` evidence carries current key state/version only when a
retained grant is currently accepted; native verification must match that
complete identity to an independent Owner pin. When evidence is absent, the
Client still needs a trusted current-key lifecycle source before claiming a
key is active. The Client has no peer Owner key pin or global key lookup, so
the other Owner's full key needs an independent trust source even when the Hub
returns it. Hub-retained identity is discovery evidence, not independent trust:
never auto-pin it. Owner proof signing remains external; the Client verifies
and submits only a proof bound to the exact freshly reviewed manifest. Do not
use a Node bearer or the Node-only relay authorization route.

The existing Link policy validator supports `NONE` without reviewer
authorization. It can be completed only after the Link authority, local Owner
pin, current key evidence and dedicated preview/grant methods are integrated;
none of the five production methods is wired now. `METADATA` additionally
depends on fresh reviewer Endpoint/Group membership and explicit `link.review`
permission. Core confirmed that the v1.6.3 preview/grant current-permission and
reviewer-lease Guard has a defect and is preparing a Core fix. The current
topology projection exposes roles and broadcast permission, not an independent
`link.review` grant. Keep `METADATA` blocked until the Core fix is delivered and
its current permission/lease behavior is verified; policy preview alone does
not establish reviewer authorization.

## Verification receipts

All executable checks below were run in the retained offline Docker
development image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`
with image pulling disabled and network disabled. Receipts, argv and logs are
retained under
`/gpu1-share/data/cicada-client/link-consent-candidate-20261002/`. No check in
this table contacted a live Hub, Node or public HTTPS endpoint.

| Check | Result | Receipt |
|---|---|---|
| JavaScript regression set | PASS, 86 passed / 0 failed, exit 0; includes seven `linkConsent` cases | `checks-final/js.receipt.json`; log SHA-256 `a7cb0994e8b7a9d2cb9f6c036f0e0e12a234229cff5d4533d029bb751276a380` |
| Kotlin pure host-JVM tests (prior source snapshot) | PASS, 16 passed / 0 failed, exit 0: 7 Link-manifest/proof and 9 policy cases, including the complete v1.6.3 public vector | `checks-final/kotlin-host.receipt.json`; log SHA-256 `0ecfa692091ddfe14103eb5ee287d434fa545ab7df2a72db3488e860c65dc853`; tested-input fingerprint `e583707b0a92050217b5ff3a977c17e412bf24f0bd2666a47371775dc8abc4a1` |
| TypeScript | PASS, `tsc --noEmit`, exit 0 | `checks/typescript.receipt.json` |
| ESLint (initial candidate run; historical) | PASS, exit 0; 26 warnings, 0 errors. Three warnings were in `src/platform/linkConsent.ts` (`no-control-regex` and two `no-bitwise`); the remaining warnings were in `App.tsx`, `LinkReviewPolicyStatusPanel.tsx`, and `NodePairingPanel.tsx`. The three module warnings were removed in the later quality-only rerun below. | `checks/eslint.receipt.json`; log SHA-256 `0b3b4670a730b12346097e37e1a55c54f2f7a6fede2af4575bb85dab0df484cf` |
| Pinned Client contract checker | PASS, exit 0 for the active v1.6.1 contract pins (21 files); this does not repin Android to v1.6.3 | `checks/contract.receipt.json`; log SHA-256 `90ca1edd7b26eca1d1b646c551ded42d6b834a50eb05130291beb73b7db1119e` |
| Contract-checker regression tests | PASS, 11 tests, exit 0 | `checks/contract-regressions.receipt.json`; log SHA-256 `f72a2aa568caecea0899c025be403f5aed8ea345bcceb2c4b80a721d9c4517da` |

The original JavaScript receipt records unchanged source before/after hash
`50a42d2cc154ad7430914e3129f7b5c4f2e60858e0addc07e513c0878bf3c08f` over
129 files. The prior Kotlin receipt records unchanged tested-input hash
`e583707b0a92050217b5ff3a977c17e412bf24f0bd2666a47371775dc8abc4a1` over
101 files; its two selected test sources are separately hashed in the receipt.
The Gradle task was `:app:testDebugUnitTest` with only
`LinkKeyManifestVerifierTest` and `LinkReviewPolicyConsentValidationTest`.
The final report says `candidate_apk: NOT_BUILT`.

### Final source quality rerun

The only source change after the original validation was lint cleanup in
`src/platform/linkConsent.ts`: control-character rejection now uses a bounded
character-code loop, and the canonical Base64 pad-bit checks use equivalent
modulo tests. The rejected byte and Base64 forms are unchanged. The runner was
copied into the exclusive evidence directory
`checks-quality-final/` so the first receipts remain intact. In the same
network-disabled Docker image, the final JavaScript regression set passed all
86 tests (0 failed, exit 0), TypeScript `tsc --noEmit` passed (exit 0), and
ESLint passed (exit 0) with 23 warnings and 0 errors. There are now zero
warnings in `src/platform/linkConsent.ts`; all 23 remaining warnings are in
`App.tsx`, `LinkReviewPolicyStatusPanel.tsx`, and `NodePairingPanel.tsx`. The
initial 26-warning receipt above is retained as historical evidence.

| Final quality check | Receipt | Log SHA-256 |
|---|---|---|
| JavaScript, 86 passed / 0 failed, exit 0 | `checks-quality-final/checks-final/js.receipt.json` | `979a8d7859e204a7c886d9050088caa2be03432dc101cf8de9811382270079b3` |
| TypeScript, exit 0 | `checks-quality-final/checks/typescript.receipt.json` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty output) |
| ESLint, 23 warnings / 0 errors, exit 0 | `checks-quality-final/checks/eslint.receipt.json` | `a7e605dd40e4e10eb33e23e9730b1ce83dda582544f52e404bc5422585af02d4` |

All three receipts report the same source fingerprint before and after:
SHA-256 `62aa83daa2e6cb6ec782309381ba73338d9d5419bd036b61a95164b1a588dabd`
over 129 files. Their tested-input fingerprint is SHA-256
`70f8a5ec000ff34dad6fba68f8c406dc7f28f64b8a00e5e7f88f2ccdad5799d5` over
41 files, also unchanged. The recorded client base is
`4c4784e9bb7eb6b64b7b31ff34d8b5862eb6c23b`.

### Final Kotlin provenance run

After the verifier Javadoc was clarified to describe the fresh encrypted Link
manifest as the caller-bound current authority, the pure host-JVM gate was run
once against the current source and imported clean public vector. This was a
documentation-only Kotlin change; verifier behavior, tests, contract pins and
vector bytes were unchanged. The offline Docker command exited 0. JUnit XML
reports 7 `LinkKeyManifestVerifierTest` cases and 9
`LinkReviewPolicyConsentValidationTest` cases: 16 total, 0 failures, 0 errors
and 0 skipped. The imported clean vector and Android test asset are
byte-identical, both SHA-256
`aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d`.
The isolated evidence root is
`/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final-bound-e8/`;
receipt, log and JUnit paths in the table below are relative to that directory.
Source and vector paths are repository-relative.

| Final Kotlin evidence | Path | SHA-256 |
|---|---|---|
| Host gate receipt | `checks-final/kotlin-host.receipt.json` | `a55523394cec082a3415e20f598c6457fec9ec96fbf2679b70a38385fe8c9ee3` |
| Gradle log | `checks-final/kotlin-host.log` | `73a08c25ff7dc0c51d157ca70a339ab561fbc4ab3111bffe7ee912a4768b9a88` |
| Manifest verifier source | `android/app/src/main/java/ai/cicada/client/hub/LinkKeyManifestVerifier.kt` | `142080c95936d1908caa4b7e2c3ce2980970512a46e8c1b1f17040fc9a72f717` |
| Clean Core vector and identical Android test asset | `contracts/client-hub-v1.6.3-e8a029d/cicada-go/internal/e2ee/testdata/link-client-proof-v2.json`; `android/app/src/androidTest/assets/link-client-proof-v2.json` | `aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d` |
| `LinkKeyManifestVerifierTest` JUnit XML, 7 passed | `checks-final/junit/TEST-ai.cicada.client.hub.LinkKeyManifestVerifierTest.xml` | `f54b620dff93c4716e0db3736a3f8142d51a789a1df2db0650eab042346b9b5b` |
| `LinkReviewPolicyConsentValidationTest` JUnit XML, 9 passed | `checks-final/junit/TEST-ai.cicada.client.hub.LinkReviewPolicyConsentValidationTest.xml` | `d18be47c8024f228ad922d9e408cc4aec6189e0edf8ea5ba2520f68b54072512` |

The receipt records unchanged full source fingerprint
`fdd6b5ed46272f841a5615c2adaba3f6d23ee36c9c085633cbc81c2476f60ca6` over
129 files and Kotlin-tested-input fingerprint
`306b12306049104005feca264a4530728aacad2ab709a4493170391374603604` over
101 files. The selected original test files are separately hashed in the
receipt. The prior 16-test pass remains preserved at
`/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final/kotlin-host.receipt.json`;
the initial compile and fixture-boundary
failures and their corrections remain recorded below. This final run is a
host-JVM test only: no APK, emulator, device or native production path was
built or exercised.

### Initial failures and corrections

The first host Kotlin run exited 1 during test compilation because the
external test source called unresolved `replaceFirst` at
`LinkReviewPolicyConsentValidationTest.kt:156`. That test-only source was
corrected; production code and validation strength were not changed.

The next run compiled but exited 1 on
`GoPolicyDigestUsesExactStructOrderAndDefaultHtmlSafeEscaping`: the fixture put
U+2028/U+2029 at the end of identifier strings, where the validator correctly
rejected the trimming boundary. The fixture was changed to place those
characters inside the IDs (with trailing `end` text). No verifier logic or
acceptance rule was weakened. The final 16-test run then passed. Initial and
corrected receipts remain in `checks/` and `checks-corrected/` alongside the
final records.

## Explicitly not verified

No Android APK was built, installed or run. No real-device, native Runtime,
model, clean-v1.6.3 Hub interoperability, production Link grant, reviewer
permission, persistence/recovery over a live Hub, or public HTTPS acceptance
is claimed. The five Link operations remain closed pending a dedicated native
integration that binds and re-fetches the encrypted, server-authoritative
two-sided manifest, independently trusted Owner keys, and a Core fix plus
verified current `link.review` permission and reviewer lease for `METADATA`.
