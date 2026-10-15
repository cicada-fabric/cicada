# Client-Control v1.6.4 validation — Core 25bc586

## Scope and attribution

This record covers the clean Core delivery and the current v1.6.4 Link consent
candidate. The accepted Android baseline remains Core 144e079 /
Client-Control v1.6.1; its APKs and test results do not certify this release.
The prior Client checkpoint is `36f127ef3e7b19fedf1f29e40be63a881f8baa17`.
The final offline retry-6 x86_64 candidate is recorded by the Client milestone commit; its exact commit identity is in the external delivery receipt
`/gpu1-share/data/cicada-client/v164-25bc586-20261002/client-delivery.redacted.json`. Its five dedicated Link consent methods are enabled locally behind Native, Hub metadata and encrypted
session capability checks; generic RPC still rejects those five operations.
Retry-6 passed 40 pure Kotlin host tests across five classes (Factory 6, Ledger
5, Key 7, Policy 9, Evidence 13), with no failures or skips. Full Native and
Android-test Kotlin compilation plus both Debug x86_64 APK assemblies exited
0. The host receipt SHA-256 is
`fa7bfc446aa3d0c9ce3b0b305b24cc458e95cbb7b6d444b50d96a3bbf6c3bd94`; app/test
APK hashes are
`56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` /
`caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`. The
artifact receipt SHA-256 is
`e42968ad186bf8211e52639eb7ede11d4473a5730cfeb0f110682faf52d8a968`; the
153-file snapshot SHA is
`b6f8eb00b9a0ad61c7fd31947e1925f8d77b15c5ad23d56d39476e26f7d81a80`, source
fingerprint (140 files) is
`855087a657384177343b6b8868ca51a6d5bfc5a3983382c01b9e7b0e928a2431`, and
Kotlin fingerprint (110 files) is
`8276380239debfe1dd735636037efc5662656d6835da490342bd25ecb6fe7b1e`. A
bounded ZIP-name/public-vector resource scan passed for this pair (receipt
`final-privacy-retry6.redacted.json`, SHA-256
`262d0bc2bee8d7ee2b715ad997f78e978fbaf2b9c6496c57373301dea798b0f1`). The
new pair has not been installed or run in an emulator/live fixture and inherits
no earlier test results. The old 38 Kotlin / 47 Android test results remain
tied only to retry-4 app `1811e156012eb4996c8740ab875d4ac142bb1979ba0f1b0cfe94c1b6a9b4686e`
and test APK `d22756ee8169263b5142997b08825dda60f12331734f923ea7c005965a42c288`.

F5's actual live attempt used app `1811…b4686e` with test-only be72 and failed
before Source proof signing. Ten steps passed through Source KEY manifest read
and request export; the signer rejected a noncanonical RFC3339Nano maximum
expiry (`2026-10-02T15:27:50.050630Z` versus canonical same instant
`2026-10-02T15:27:50.05063Z`). No signature, Source KEY grant or policy grant
was created; Target enrollment, Alert and policy were `NOT_RUN`; bilateral KEY
and NONE remain `BLOCKED`. The F5 live run exited 1; outcome SHA-256 is
`fb0c0ae79b8ca62100ac155def3e3d83dd674169ab7fee15c000c1d6d5bd3078`, live exit
receipt SHA-256 is
`6be58fbf228285506a66be124aaf0ab64ba284200ab30a8ff6722188e0dcdae1`. F5 was
not retried with a new proof or nonce. Core requires a new scope before another
live attempt. The F5 carrier stopped after 11 transactions with no payload
persisted, and its cleanup addendum records five owned IDs absent while Core
attests six resident resources unchanged (receipt SHA-256
`889655487ae8cb700c40cd5d7ca0a7ecf6bfb6e804ba539d113616d44836eba7`).

Retry-4's 38/47 results, the earlier F3/F4 UI failures and all F1/F2 attempts
are retained below with their original app, test and Core fixture attribution.
This remains an uncommitted local candidate, not an accepted release.

## Fixed delivery

| Item | Independently checked value |
|---|---|
| Core commit | `25bc586232db43362c6e03eccef1fa3a0dbec8ee` |
| Protocol / wire / schema / catalog operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Archive SHA-256 | `1dd627c591faf2413ffa29e2cfac4d608698ef494af3cb1d5063c37ccf724f2c` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Core build-input fingerprint, 882 entries | `4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032` |
| Hub image ID | `sha256:41b7a968293f14d7b7472333dcf64980e95eb68868e85dfdd71fa850f4eecbb4` |
| Interop image ID | `sha256:bcb8856c3d766c54c53e6c1dc1dcbe32beb2806c02260442610fde1af21cb6b1` |
| Public bilateral policy vector SHA-256 | `aeb0985056e305a2ea06616e39bebd2bd58957efe61d5e2be9511f6a52039bcd` |
| Producer receipt SHA-256 | `00799c4094dc63406156eaabc86ee3f4ae7f2e47452c52086803602c81c61345` |

The archive is imported into `contracts/client-hub-v1.6.4-25bc586` without
modifying prior snapshots. The manifest reports `source_dirty=false`; its exact
24 payload files, byte counts and hashes were checked before extraction. Both
immutable local image IDs and source, catalog and clean-build labels match the
producer. The Client's independent verifier reconstructs the build-input
inventory against the pinned Git objects. Raw permission bits are captured
producer metadata; this verification does not claim a current-worktree mode
observation or that image execution has passed.

## Evidence and commands

Restricted evidence directory:
`/gpu1-share/data/cicada-client/v164-25bc586-20261002`.

| Command | Exit | Result | Evidence |
|---|---:|---|---|
| `python3 …/import-and-provenance.py`, initial attempt | 1 | FAIL | `provenance-initial-failure.redacted.json` |
| Same command, corrected read-only Docker UID | 0 | PASS | `provenance.redacted.json` |
| Docker `verify-hub-input-inventory.py`, complete argv in provenance receipt | 0 | PASS | `independent-source-inventory.redacted.json` |
| Docker `check-client-contract.py --snapshot-dir contracts/client-hub-v1.6.4-25bc586` with complete fixed revision/catalog flags | 0 | PASS | `contract-check.redacted.json` |
| Earlier crypto-only Kotlin snapshot setup/compile attempts | 1 each | FAIL; historical component attempts, not current Native integration | `crypto-initial`, `crypto-retry-1` through `crypto-retry-4` |
| Earlier crypto-only Kotlin snapshot with four exact selectors | 0 | PASS, 34 tests, no skips; does not certify current Native integration | `crypto-retry-5/checks-final/kotlin-host.receipt.json` |
| Earlier JavaScript snapshot | 0 | PASS, 95 tests; superseded as current candidate evidence | `checks-ui-final/checks-final/js.receipt.json` |
| Earlier TypeScript attempt and correction | 2 then 0 | Initial capability-helper failure, then PASS on earlier UI snapshot | `checks-ui-final/checks/typescript.receipt.json`, `checks-ui-retry-1/checks/typescript.receipt.json` |
| Earlier ESLint run | 0 | PASS, 23 warnings; current candidate lint is listed below | `checks-ui-final/checks/eslint.receipt.json` |
| Docker external signer tests, initial offline missing exact cached module | 1 | FAIL before compilation | `signer-check/receipts/signer-validation.receipt.md` |
| Same pinned archive, exact offline module cache, `go test -mod=readonly -count=1 ./cmd/groupownersigner` | 0 | PASS, 7 tests | Same receipt |
| Pinned Go builder, `go build -mod=readonly -trimpath … ./cmd/groupownersigner` | 0 | PASS | Same receipt |
| Current-default contract checker | 0 | PASS | `checks-contract-current/checks/contract.receipt.json` |
| Contract regression suite, old metadata equality expectation | 1 | FAIL, one assertion | `checks-contract-current/checks/contract-regressions.receipt.json` |
| Contract regression suite after comparing retained IDs and verifying metadata through the fixed digest | 0 | PASS, 11 tests | `checks-contract-retry-1/checks/contract-regressions.receipt.json` |
| Corrected full Native candidate Docker command: `gradle --offline --no-daemon … :app:testDebugUnitTest` (five Link selectors), `:app:compileDebugAndroidTestKotlin`, `:app:assembleDebug`, `:app:assembleDebugAndroidTest`, `-PreactNativeArchitectures=x86_64` | 0 | PASS, 38 unit tests, no skips; Android-test Kotlin compilation and both APK assemblies passed on retry-4 | `candidate-build-retry-4/checks-final/kotlin-host.receipt.json`, SHA-256 `b0c9da8c8d80a2cb4c23c5080e84c43e63139c3325bff4f5032cb2581aca2833` |
| Retry-6 full Native offline build | 0 | PASS: 40 pure Kotlin host tests across five classes (Factory 6, Ledger 5, Key 7, Policy 9, Evidence 13); no failures/skips; Native and Android-test Kotlin compile and both Debug x86_64 APK assembly passed | Host receipt SHA-256 `fa7bfc446aa3d0c9ce3b0b305b24cc458e95cbb7b6d444b50d96a3bbf6c3bd94` |
| Retry-6 app/test APK artifacts | 0 | PASS build; app/test pair is `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` / `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`; no runtime result for this pair | Artifact receipt SHA-256 `e42968ad186bf8211e52639eb7ede11d4473a5730cfeb0f110682faf52d8a968` |
| Retry-6 source inventory | PASS | 153-file snapshot; source fingerprint covers 140 files and Kotlin fingerprint covers 110 files | Snapshot SHA-256 `b6f8eb00b9a0ad61c7fd31947e1925f8d77b15c5ad23d56d39476e26f7d81a80`; source fingerprint `855087a657384177343b6b8868ca51a6d5bfc5a3983382c01b9e7b0e928a2431`; Kotlin fingerprint `8276380239debfe1dd735636037efc5662656d6835da490342bd25ecb6fe7b1e` |
| Retry-6 bounded APK resource scan | PASS, bounded | Entry names and public vectors only; no sensitive entry names and no private-key bytes read | `final-privacy-retry6.redacted.json`, SHA-256 `262d0bc2bee8d7ee2b715ad997f78e978fbaf2b9c6496c57373301dea798b0f1` |
| Earlier Docker Node test runner, 12-file candidate suite | 0 | PASS, 90 tests, no skips; separate from the corrected Native build inventory | `checks-candidate-retry-1/checks-final/js.receipt.json` |
| Docker TypeScript `tsc --noEmit` | 0 | PASS on the earlier 139-file candidate snapshot; separate from the corrected Native build inventory | `checks-candidate-final/checks/typescript.receipt.json` |
| Docker ESLint | 0 | PASS on the earlier 139-file candidate snapshot, 23 existing warnings and no new warnings; separate from corrected Native build inventory | `checks-candidate-final/checks/eslint.receipt.json` |
| Initial x86_64 app/test candidate (`a39ff773…91a192` / `0b6cca72…6752f3f`) | 0 | Build passed; its separate resource check failed. Retained as history only. | `candidate-build-initial/build-artifacts.redacted.json`; original emulator evidence retained separately |
| Superseded retry-2 APK (`ab2226c8…545ea3` / `1446ff12…a530a`) and its 47-test/UI results | 0 | Earlier emulator/UI checks passed before the Endpoint fingerprint-domain correction; no result transfers to retry-4. | Prior `candidate-build-retry-2` and archived Android summaries |
| Corrected retry-4 x86_64 emulator app and Android-test APK build | 0 | PASS; private DEBUG-signed candidate artifacts | `candidate-build-retry-4/build-artifacts.redacted.json`, SHA-256 `725f77f06157aa51bf427009d2a8b3dc9f2d2f9feebfac9930412dfffb11bff5` |
| Current retry-4 APK Android emulator tests | 0 | PASS, 47 tests across 7 classes after reinstalling with `adb install -r` on the same owned emulator; Source Keystore/Grant preserved | `/gpu1-share/data/cicada-client/v16-deterministic-v164-25bc586-r2-20261002/android/deterministic-summary.redacted.json`, SHA-256 `3d6c4eaf60fb2707e21a2873013a55019f2b9b606bcd590a31a91a64424c3212` |
| Retry-4 five-check product UI smoke | NOT_RUN | This separate five-check smoke has not been run on retry-4; F3's actual UI step is recorded below. | No execution receipt |
| Corrected UI test-only APK, first build attempt | 1 | FAIL during read-only NodeModules setup; no APK result. | `phone-ui-build-retry-1`, receipt SHA-256 `9140500e590d265c6647e726fd34bf3c8378b47d64b1bbd2a28974c6b18c864e` |
| Corrected UI test-only APK, retry-2 build | 0 | PASS; instrumentation APK SHA-256 `84794cc312a22af367718bd78fb389a0ade49fff125a130b900cb08157835f64`. | `phone-ui-build-retry-2`, receipt SHA-256 `5844d1cb11b7029618231798f57a27247f60f5547811f7b211d21ef5356b013d` |
| Corrected UI test-only APK installation | 0 | PASS on unchanged app APK `1811e156…b4686e`; the first host-path invocation stopped before install because Docker ADB could not see that path. Corrected Docker-side copy/install completed and this APK was used by F4's actual UI attempt. | Install receipt SHA-256 `8c81b7c9c0c268f47f363e8819fe7c6057513c89bafc5c6ecf511267ea997adf` |
| F1 live Hub attempt | — | INCOMPLETE: expired before enrollment; no Owner enrollment or consent. Its carrier stopped with zero transactions. Core-owned cleanup receipt SHA-256 `5cd5f1567bf7598c5bffc20fda254607ae7d61d8b2876ddaca6e638683bc62bf`. | Root-owned F1 evidence |
| F2 setup and Link prepare on retry-2 APK | 1 | Overall FAIL. Source device export, external OwnerDeviceGrant, enrollment and fresh encrypted capabilities passed; Link key prepare then failed its local scope/domain comparison before any Link grant. | `live-inputs-f2/live-exit-retry-2.redacted.json` |
| F2 retry-2 carrier shutdown | 0 | PASS; 11 transport transactions recorded. This does not establish a Link grant or consent. | `stdio-carrier-link-v164-f2-stopped.redacted.json` |
| F2 same-emulator retry-3 resume | 1 | Historical FAIL; reused saved Source enrollment, submitted one SOURCE key grant, received `ok=true`, then rejected post-submit status as `LINK_KEY_GRANTS_INVALID`; no duplicate submit was made. | `live-inputs-f2/live-exit-resume-r3.redacted.json`, SHA-256 `7fe239b8adfa6a89f1fac761bb62a2dc4bb52439549d2ebf986d0b4e2c5c0b73` |
| F2 retry-3 clock-sync status and policy candidate | — | Historical: before emulator clock sync, status returned `LINK_KEY_GRANTS_INVALID`; after sync, status progressed on the same Source proof. The later policy candidate failed `LINK_CONSENT_REVIEW_INVALID` because the NONE ledger had an empty reviewer set. No policy write was performed. | `live-first-key-and-none-failures.redacted.json`, SHA-256 `841d9d6a8c3e26c984f0dadacc837d902d77c3ad0e55e97d25643162fe033cae` |
| F2 retry-4 same-emulator renewal | 1 | FAIL; new explicit consent and nonce followed expiration of the earlier completed Source proof. Fixed Hub returned `ok=false` for the prior-grant conflict; no automatic or further write retry. | `live-inputs-f2/live-exit-renew-r4.redacted.json`, SHA-256 `807f9f465f1c5423e9a05f571b936161ead4c97c8606f16366fcaf6af28ee011`; refusal receipt `f2-renewal-refusal.redacted.json`, SHA-256 `1bf5bb2bf10aa8010e9594cd5b5841388db4a59fd1634b590a78ec60a96c47bd` |
| F2 carrier shutdown after retry-4 refusal | 0 | PASS; stopped with 16 transport transactions and no payload persisted. | `android/stdio-carrier-link-v164-f2-r4.redacted.jsonl`, SHA-256 `356bb6597e91d6056a394f034538d35342d336e80cde9c8deac418d33ef0e85d` |
| F3 Core fixture | READY | Trusted Core READY receipt and four public pins received; exact public hashes recorded below. | Core fixture-03 handoff |
| F3 setup and first 27 Client steps | 0 | PASS, scoped: Source KEY submission and fresh single-side status; Source NONE policy candidate at fresh head 0; Target enrollment, fresh capabilities and independent pins. No bilateral result. | `f3-outcome.redacted.json`, SHA-256 `983ecbf1d03d818d63e03d5257af5bd3a28a87dd0ec43e5db8b70a18e235ae4d` |
| F3 actual React Native UI, step 28 | 1 | FAIL: selector expected `重读本人提案`; rendered section label includes `→`. Failure was before request export/signing and before any Target write. | `live-inputs-f3/live-exit.redacted.json`, SHA-256 `5261f71399c45e42a4c6843266c3f91a332768f122acebf2a5cf638642dd9815`; outcome receipt above |
| F3 wrong-pin and generic-RPC refusal checks | 0 | PASS, one JUnit test; sequence unchanged and no pending operation created. | Refusal receipt SHA-256 `4ff17319ab838e366346c630b61d027f44d148b3b3801af54cf0538600dd84f0` |
| F3 carrier and cleanup handoff | 0 | Carrier stopped after 68 transactions; Core cleanup acknowledgment sent. | Outcome receipt above; carrier SHA-256 `0cfb57ede63ade02ac7e912b80b86d0e275cb071688401485a7158692ee71a3b` |
| F3 aggregate outcome | FAIL | Source proof expired at `2026-10-02T13:44:08.366725Z`; bilateral status is `BLOCKED_SOURCE_PROOF_EXPIRED`; no renewal, Target key write or Target policy write. | `f3-outcome.redacted.json`, SHA-256 above |
| F4 final Core fixture | READY | Trusted final READY receipt and public setup/reference/Hub manifest hashes recorded below. | `f4-outcome.redacted.json`, SHA-256 `2f50a815ea9b730dd8f4b673b7a08d6cb9b95519e47a28ba0a913e4662b0c5d3` |
| F4 metadata preflight attempts | 1 each | Both FAIL before Client RPC (RPC count 0): helper mode differed from F3; then Core's explicit network rename invalidated the retained HostConfig alias. Full-ID and label guards remained enabled. | Preflight outcomes in `f4-outcome.redacted.json` above |
| F4 first 27 Client steps | 0 | PASS, scoped: Source KEY and fresh one-side status; Source NONE candidate and fresh head status; Target enrollment, fresh capabilities and pins. | `f4-outcome.redacted.json`, SHA-256 above |
| F4 actual React Native UI step 28 | 1 | FAIL after Target request export, Host signing and proof paste: confirmation control was outside viewport; automation did not find/click it and Alert was not clicked. Zero Target KEY writes; Target policy write NOT_RUN. | Live command receipt SHA-256 `842c7808794b42d9bb4d758052b1e4055b16d9bbb273affd9f33e556833eb57a`; JUnit `FAIL_missing_confirmation_control_after_multiline_proof_expanded` |
| F4 aggregate outcome | FAIL | Source proof expired at `2026-10-02T14:22:35.145809Z`; bilateral current is `BLOCKED_SOURCE_PROOF_EXPIRED`; F4 made no renewal or follow-up write. | `f4-outcome.redacted.json`, SHA-256 above |
| F4 final confirmation-scroll test-only APK build | 0 | PASS; test APK SHA-256 `b4c1b4910c4ebaf18a861f7da6d153b016cb8a2e45fe7f044bf442d485397733`. | Build receipt SHA-256 `12f192c9ae77e9d1063c58bfa9a1b1e48144ef61c41dec595fe68727ca3b7a84` |
| F4 final test-only APK use | NOT_RUN | APK `b4c1…5397733` was built after F4 and was not used by that run. It was later installed for F5 preparation, then superseded by be72. | `f4-outcome.redacted.json`, SHA-256 above |
| F4 carrier and owned emulator cleanup | 0 | 74 transactions stopped; owned emulator stopped/absent. Core cleanup continuation attests only F4/F5-owned resources removed and six resident resources unchanged; Client read-only audit found five owned IDs absent. | Carrier SHA `afb3ae8f90cb92d20a45ac483136c4e71ef6b9eb412d2d9bface1620f3ba7462`; Core `8fd62afe8841400c2b1e7fb6d7ac0ddbf0ce4ce6907054e766830ad8e6742305`; Client `889655487ae8cb700c40cd5d7ca0a7ecf6bfb6e804ba539d113616d44836eba7` |
| F5 bounded app-source comparison | PASS | 54 `App.tsx`/`src/main` Kotlin files match retry-4 compiled app source; no missing/different files. Not the full 153-file snapshot; does not transfer 38/47 tests. | `private/final-app-source-comparison.redacted.json`, SHA-256 `e2e3529f3c34ab6238988b0b84d1db1d631e1654453999c208eb543db42a3731` |
| F5 final UI test-only APK build | 0 | PASS, APK SHA-256 `be72fa25371c2494969888d77f60b1019e49d654bc0c1d81602da60ff92ee674`; source SHA-256 `12cf4088ae39e7696f57d272f8de1cbe996325cea189a1234fb9819531a167ad`; app `1811…` unchanged. | Build receipt SHA-256 `b5170dab8daf78897a84f6b15f189b5d07ca070b095986321b4cdd6f3589d3e0` |
| F5 final UI test APK installation | 0 | PASS on r3 emulator; install receipt SHA-256 `2310d2c376c079c9b671978119c81ff5e5bf3bb0f5b5e80d31d6bf5e28936cd1`. `sys.boot_completed=1`; clock adjustment exit 0. | Root-reported r3 preparation receipts |
| F5 final APK resource-boundary check | 0 | PASS, bounded ZIP names and AndroidManifest metadata: app excludes public vectors; be72 test APK contains them; no sensitive-looking entry names. No private key bytes read. | `final-privacy-be72.redacted.json`, SHA-256 `6e8c7505295036a7679a59ac2dc8beda35127705cbef8d722f7a03f7272e9b46` |
| F5 artifact freeze | PASS | App `1811e156012eb4996c8740ab875d4ac142bb1979ba0f1b0cfe94c1b6a9b4686e` and test-only APK be72 frozen; 54 app-source files match retry-4 compiled source. | `f5-artifact-freeze.redacted.json`, SHA-256 `66a444c02b9b1fbf9083f8bd492837ba773ee078d3e4788ce33ac607c1d664c1`; source comparison SHA-256 `e2e3529f3c34ab6238988b0b84d1db1d631e1654453999c208eb543db42a3731` |
| F5 Docker read-only preflight | PASS | Exact pinned fixture image/container/network metadata validated without Client RPC or Hub writes. | `f5-docker-readonly-preflight.redacted.json`, SHA-256 `6e436973eb76c8363a618cedc2f8770eccdc2a8d762e2b7a7200f83761ecd14d` |
| F5 Core fixture | READY / GO | Trusted READY and Root GO received; public fixture pins recorded below. Client did not perform database operations. | READY receipt SHA-256 `c9c67e4066928c6d4735c6d61f6ee06fb763197c3cc134189e237da257ddbae3`; Root GO receipt SHA-256 `654155868506553cd0d3702e836d7f6427b6552a4b18a30aa18ce561f490b559` |
| F5 initial local runtime preflight | FAIL, exit 1 | Missing runtime observation prevented entry to business flow: zero RPCs, selectors, signer calls, operations or pending packets. Failure was retained. | `live-inputs-f5/preflight-runtime-failed/live-exit.redacted.json`, SHA-256 `ffece6e92d7e80094e596446fad4dbef452b4f03c6bd624fc7add46760ae625d` |
| F5 runtime observation | PASS, exit 0 | Four ADB `getprop` reads recorded SDK 35 / Android 15 / x86_64 / qemu; no business retry. | Observation SHA-256 `0498a54be328804415a683d1684d3550758b660bbfa0dd69dd50a7f6762c5a0f`; correction receipt SHA-256 `e1fd8650c032e4617b2a4e34c796ebbb2b0ec3506607a87b4a474078fcaa6bd0` |
| F5 Client flow | FAIL, exit 1 | 10 steps passed through Source KEY manifest and export. `source-key-sign` exited 2: max expiry had noncanonical RFC3339Nano fractional zeros (`.050630Z` versus canonical `.05063Z`, same instant). No signature, Source KEY grant or policy grant was created; Target enrollment/Alert/policy were NOT_RUN; bilateral KEY and NONE remain BLOCKED. | `f5-outcome.redacted.json`, SHA-256 `fb0c0ae79b8ca62100ac155def3e3d83dd674169ab7fee15c000c1d6d5bd3078`; live exit receipt SHA-256 `6be58fbf228285506a66be124aaf0ab64ba284200ab30a8ff6722188e0dcdae1` |
| F5 carrier / emulator cleanup | 0 | 11 transactions stopped with no payload; owned emulator stopped/absent. Core cleanup continuation attests six resident resources unchanged; Client read-only audit found five owned IDs absent. | Carrier `03e1c4638dfc87fad031c8a0b2f0f5fa8b717c41ec635dbe7e27c294c7b0825c`; Core `8fd62afe8841400c2b1e7fb6d7ac0ddbf0ce4ce6907054e766830ad8e6742305`; Client `889655487ae8cb700c40cd5d7ca0a7ecf6bfb6e804ba539d113616d44836eba7` |
| Successful bilateral Link consent/recovery | NOT_RUN | No passing terminal receipt or phone confirmation | No bilateral result |
| Native full-integration compile attempts | 1 each | Initial scope/Gson helper failure and retry `JsonArray.isNotEmpty` failure retained; corrected candidate build above passes | `native-full-initial/checks-final/kotlin-host.receipt.json`, `native-full-retry-1/checks-final/kotlin-host.receipt.json` |
| First full candidate JavaScript run | 1 | FAIL, 89/90; a legacy shared-space assertion still expected 16 closed operations. Corrected retry above passes. | `checks-candidate-final/checks-final/js.receipt.json` |

Core F3 fixture setup is READY at
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-03-20261002`.
Its trusted `evidence/ready-receipt.json` SHA-256 is
`23c86426770a5fb12bbff639abed0d62d0fcc4e300e32caa3f3e383f30a9a8ee`;
`public/client-setup.json` is
`f1c4fc09c2e3ffe380358ab570c126ab88ff3d024a1c9510986603b000e11af2`,
`public/reference-manifest.json` is
`e86edd67ec278dfb15580280f880a3c61093a9ec69e634418091c3555e85e62e`, and
`evidence/owned-hub-manifest.json` is
`aa758cdaef7dfe850c1740887d3375ee2a8660c5aae708668eb9d1fef33d6272`. The
Core public fixture SHA-256 is
`82cf50377beef525f561dd937a95c8b5bc089a817585ed8bb7f86fd158e98831`. These
are setup pins only. F3 later passed 27 scoped Client steps and failed its
actual React Native UI selector at step 28 before request export, signing or a
Target write. The aggregate outcome receipt is
`/gpu1-share/data/cicada-client/v164-25bc586-20261002/f3-outcome.redacted.json`,
SHA-256 `983ecbf1d03d818d63e03d5257af5bd3a28a87dd0ec43e5db8b70a18e235ae4d`.
The live command exited 1 (receipt SHA-256
`5261f71399c45e42a4c6843266c3f91a332768f122acebf2a5cf638642dd9815`). The
Source proof expired at `2026-10-02T13:44:08.366725Z`; bilateral current status
is `BLOCKED_SOURCE_PROOF_EXPIRED`, and no renewal was attempted.

Core's final F4 fixture-04 public pins are: READY receipt SHA-256
`afa44fc971d9e28e27a8a7b12b86b3180b419c9923da50532944345711fbd3e5`,
`client-setup.json` SHA-256
`f070b8624a13305b4d150b5ae95e71d8b946a2cd6a2919240557da3f32d8c51b`,
`reference-manifest.json` SHA-256
`b9ccd38a6b6e134182dd9b68127fba8c286e989e89e0c069559cbea839e2c619`, and
`owned-hub-manifest.json` SHA-256
`8f73b2f11914a1e45dddb381278e432ed3ac1f25c5a1b163e3a14462eb08e242`. The
F4 aggregate receipt is
`/gpu1-share/data/cicada-client/v164-25bc586-20261002/f4-outcome.redacted.json`,
SHA-256 `2f50a815ea9b730dd8f4b673b7a08d6cb9b95519e47a28ba0a913e4662b0c5d3`.
F4's first 27 steps passed. In step 28, the actual React Native UI exported a
Target request, obtained the external Host signature and pasted the proof, but
the confirmation control was outside the viewport after the multiline proof
expanded. Automation did not click the control or Alert, so no Target key write
occurred; Target policy was not written. The attempt exited 1 (live receipt
SHA-256 `842c7808794b42d9bb4d758052b1e4055b16d9bbb273affd9f33e556833eb57a`).
The Source proof expired at `2026-10-02T14:22:35.145809Z`, bilateral current status
is `BLOCKED_SOURCE_PROOF_EXPIRED`; F4 made no renewal or further write. F5 was
a separate later run. The 74-transaction carrier stopped with exit 0. The
owned emulator stop/absence check passed. Core cleanup continuation records
removal of only owned F4/F5 resources and no change to six resident resources
(receipt SHA-256
`8fd62afe8841400c2b1e7fb6d7ac0ddbf0ce4ce6907054e766830ad8e6742305`); the
Client's independent read-only exact-ID audit found five owned IDs absent (receipt SHA-256 `889655487ae8cb700c40cd5d7ca0a7ecf6bfb6e804ba539d113616d44836eba7`). The final test-only
confirmation-scroll APK b4 was built after F4 and was not used in that run; it
was superseded by be72. The bounded be72 privacy check passed (receipt SHA-256
`6e8c7505295036a7679a59ac2dc8beda35127705cbef8d722f7a03f7272e9b46`): the app
APK excludes public test vectors, the test APK contains them, and no private-key
bytes were read. F5 failed before signature generation as detailed above; be72
has no test result and inherits no retry-4 results. F4 made no model calls;
native runtime, physical Android and public HTTPS remain `NOT_RUN`. No
successful bilateral consent, Client commit, push, merge or deployment is
claimed.

## F5 outcome and retry-6 candidate

Core's trusted F5 READY receipt is SHA-256
`c9c67e4066928c6d4735c6d61f6ee06fb763197c3cc134189e237da257ddbae3`; public
setup, reference-manifest and owned-Hub-manifest hashes are
`c1850817ff988f47cf56a42c22640a2d533474632face4ee471a71743ca4c25e`,
`b3241ea8a53901f32c68af544384ce3f12ea46e39fe92269c8d4eea55fa32abc`, and
`a29bb094ce58ad2a817c7075923ddab2ea65f0d37d54ed54a849282e394f7b6b`.
Root GO receipt SHA-256 is
`654155868506553cd0d3702e836d7f6427b6552a4b18a30aa18ce561f490b559`.

The first F5 local preflight exited 1 because a runtime observation was
missing. It stopped before any RPC, UI selector, signer call, operation or
pending packet. The retained failure receipt SHA-256 is
`ffece6e92d7e80094e596446fad4dbef452b4f03c6bd624fc7add46760ae625d`. Four
read-only ADB `getprop` calls then exited 0 and recorded SDK 35, Android 15,
x86_64 and qemu (receipt SHA-256
`0498a54be328804415a683d1684d3550758b660bbfa0dd69dd50a7f6762c5a0f`); these
were environment reads, not a business retry. The corrected local preflight
receipt SHA-256 is
`e1fd8650c032e4617b2a4e34c796ebbb2b0ec3506607a87b4a474078fcaa6bd0`.

The live Client command exited 1 after 21.22 seconds. Ten steps passed through
Source KEY manifest read and request export. `source-key-sign` exited 2 with
`CLIENT_SIGNING_REQUEST_NONCANONICAL_RFC3339NANO`: maximum expiry was
`2026-10-02T15:27:50.050630Z` instead of canonical `2026-10-02T15:27:50.05063Z`
(the same instant). No signature, Source KEY grant or policy grant was created;
Target enrollment, Alert and policy were `NOT_RUN`; bilateral KEY and NONE are
`BLOCKED`. No new nonce, proof retry, renewal or F6 run occurred. Outcome
receipt SHA-256 is
`fb0c0ae79b8ca62100ac155def3e3d83dd674169ab7fee15c000c1d6d5bd3078`; live exit
receipt SHA-256 is
`6be58fbf228285506a66be124aaf0ab64ba284200ab30a8ff6722188e0dcdae1`. The
carrier stopped after 11 transactions with no payload persisted (receipt
SHA-256 `03e1c4638dfc87fad031c8a0b2f0f5fa8b717c41ec635dbe7e27c294c7b0825c`).
Core cleanup continuation records removal of only owned F4/F5 resources and
six resident resources unchanged; Client's read-only exact-ID audit found five
owned IDs absent (receipt SHA-256
`889655487ae8cb700c40cd5d7ca0a7ecf6bfb6e804ba539d113616d44836eba7`). No
fixture directory deletion is claimed.

Retry-6 is the final offline candidate. The host test suite passed 40 pure
Kotlin tests across five classes (Factory 6, Ledger 5, Key 7, Policy 9,
Evidence 13), with no failures or skips. Native and Android-test Kotlin
compilation plus both Debug x86_64 APK assemblies exited 0; host receipt
SHA-256 is `fa7bfc446aa3d0c9ce3b0b305b24cc458e95cbb7b6d444b50d96a3bbf6c3bd94`.
App/test APK SHA-256 values are
`56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` /
`caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6`; artifact
receipt SHA-256 is
`e42968ad186bf8211e52639eb7ede11d4473a5730cfeb0f110682faf52d8a968`. Snapshot
fingerprints: 153-file snapshot SHA-256
`b6f8eb00b9a0ad61c7fd31947e1925f8d77b15c5ad23d56d39476e26f7d81a80`, 140-file
source `855087a657384177343b6b8868ca51a6d5bfc5a3983382c01b9e7b0e928a2431`,
and 110-file Kotlin `8276380239debfe1dd735636037efc5662656d6835da490342bd25ecb6fe7b1e`.
Bounded ZIP-name/public-vector privacy review passed (receipt SHA-256
`262d0bc2bee8d7ee2b715ad997f78e978fbaf2b9c6496c57373301dea798b0f1`). This
pair has no emulator or live result; retry-4's 38 Kotlin/47 Android tests and
F5's be72 failure do not transfer to it. Core requires a separately authorized
new scope before another live attempt.

## Implementation and security boundary

The candidate implements 44 of 55 catalog operations; 11 remain closed. Its
five Link consent operations use dedicated Native methods guarded by fresh
Hub metadata and encrypted session capabilities; generic RPC rejects those
operations. The authenticated `link.key_manifest` binds the current Link,
Endpoint and Group scope. Full Owner public identities are independently pinned;
Hub status alone cannot create trust, and current lifecycle state/version is
verified from fresh evidence rather than inferred from a role or
`accepted_sides`. Reviewer eligibility requires the current leased
`link.review` permission and exact Endpoint/Group binding.

Endpoint verification checks the original attestation byte SHA-256, complete
ML-DSA-65 public key and signature, Endpoint/Principal/Node/SessionBinding
identities and epochs, revisions, binding digest and manifest digest. The v1
signing preimage retains the contractual `"signature":null`; the final
attestation and Owner proof must contain valid non-null signatures.

Kotlin owns the preview tuple, canonical policy digest, expected-head CAS, exact
reviewed-body equality and Owner proof verification with the published claims
and domain unchanged. Changed scope, head, policy or reviewer qualification
requires fresh explicit consent. After external Owner signing, a one-use React Native Alert requires explicit
phone confirmation of the exact reviewed candidate before submission. The durable ledger retains the
original operation, proof, packet and sequence; uncertainty can be resolved
only against the exact original packet, while invalid status preserves the
fence. Grants do not enable ordinary peer messaging. `key_grants` status alone
is not bilateral proof. Retry-6 is offline-only and is not an accepted
production release.

| Acceptance gate | Result | Evidence or remaining requirement |
|---|---|---|
| Retry-6 pure Kotlin tests, Native/Android-test compile and APK assembly | PASS, exit 0 | 40 tests; host receipt above |
| Retry-6 app/test APK identity and bounded privacy scan | PASS, bounded | `56684d33…2bc67` / `caa8a170…07d0c6`; privacy receipt above |
| Retry-6 emulator tests or live Hub run | NOT_RUN | No new-pair runtime receipt |
| F5 live Client flow | FAIL, exit 1 | Local signing failed RFC3339Nano canonicalization before signature creation |
| Bilateral KEY/NONE consent and exact recovery | BLOCKED / NOT_RUN | No Source signature/grant; Target flow not run |
| Current native Worker/model; physical Android; public HTTPS | NOT_RUN | Separate acceptance required |

### Core follow-up

Use the retry-6 offline candidate only after reviewing its exact artifacts and
source inventory. Any future live run requires a separately authorized fresh
scope. Preserve the reviewed body and proof bytes; never accept an unsigned/null-signature final attestation or Owner proof;
preserve its contractual signing preimage. Do not change reviewed content,
extend TTL, renew an Owner proof or issue a new nonce to work around F5. Return the fixture's trusted pins, exact commands,
exit codes and redacted evidence. Do not claim Android UI or bilateral
consent until those steps actually pass.
