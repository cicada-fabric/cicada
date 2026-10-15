# Client-Control v1.6.4: F36 list-observation diagnosis

## Fixed target and tested APK pair

F36 ran Client commit `3254ba12cac22d0f77510999f53e6b6bc2c80aa8` against
the fixed clean Core target below. Findings apply to this APK pair only.

| Target field | Fixed value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / schema / operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Source state | `source_dirty=false` |
| Hub image | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| App APK SHA-256 | `5c346099b9a0f52af2f7ad1e6d453c50ff686b695d6d1706a14bee3b209f1b07` |
| Test APK SHA-256 | `74b80fd867640407eff177ff7590e5a2df8e0499e5fa535c44c0848f55cbfff1` |
| Runtime | Android emulator, API 35, x86_64 |

Evidence roots outside Git:

- `E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f36-0213538-main-20261004/android`
- `L=/gpu1-share/data/cicada-client/v164-f36-0213538-launcher-20261004`
- `O=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f36-0213538-main-20261004/outbox`

## Retained Android results

| Gate | F36 result |
|---|---|
| SOURCE enrollment and encrypted capabilities | **PASS**; v1.6.4/catalog verified; private material not exported |
| SOURCE independent Owner pins | **PASS**; native confirmation argument true, phone UI confirmation false |
| SOURCE KEY submit and fresh read | **PASS, partial**: local/SOURCE `ACCEPTED`, TARGET `MISSING`, bilateral false |
| SOURCE policy proof and fresh read | **PASS, partial**: prior grant not current; SOURCE `VERIFIED`, TARGET `MISSING`; fresh policy v0 has both sides `MISSING` |
| TARGET enrollment and encrypted capabilities | **PASS**; v1.6.4/catalog verified; private material not exported |
| TARGET independent Owner pins | **PASS**; native confirmation argument true, phone UI confirmation false |
| Target UI review / prepare / consent receipts | **UNKNOWN / NOT_RETAINED**; result stages and review/prepare/consent receipt references are null |
| Target request stage / authoritative grant response | **UNKNOWN / NOT_RETAINED**; no request stage or authoritative Target status is retained |
| Passive submit progress | **OBSERVED only**; zero events; see limits below |
| Target JUnit | **FAIL**: one test, one failure, 25.151 s; `scrollToText` line 421 called from `kt606`; wrapper error type `RuntimeError` |
| Target `NONE` and bilateral verification | **NOT_RUN / NOT_RETAINED** |
| Physical Android and public HTTPS | **NOT_RUN** |

The 405-byte progress receipt has `events=[]`; `last_ui_stage`,
`native_ok`, `reconciliation_required`, `promise_in_flight`, `error_code`, and
`viewport` are null or unknown. It reports `native_packet_pending=UNKNOWN` and
`native_session_methods_called_by_test=false`. This does not establish a UI
callback, native RPC, visible or missing response text, Target acceptance, or
Target rejection. The F36 failure is **not** the F35 `NOT_VISIBLE` observation:
F36 records no event or viewport result from which to make that comparison.
The selector cause and Target business outcome remain **UNKNOWN**.

SOURCE results are independent and partial. The KEY receipt reports SOURCE
`ACCEPTED` and TARGET `MISSING`; the policy receipt reports the prior grant
SOURCE `VERIFIED` and TARGET `MISSING`, then fresh SOURCE and TARGET `MISSING`
at policy version zero. These results do not establish bilateral consent.

## Terminal and cleanup

The launcher terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`** and
records `CORE_ACK_NOT_SENT`. Root separately attests one ACK exit 0; keep that
attestation distinct from the terminal field. No Core closure receipt was
reviewed for this report, so no independent Core business or acceptance result
is claimed. Do not retry or replace the unknown Target operation.

Android teardown and the separate emulator absence check both report **PASS**.
This is emulator cleanup evidence, not physical Android acceptance.

## Diagnostic successor boundary

The next source checkpoint is
`V=/gpu1-share/data/cicada-client/v164-f36-list-observation-20261004`. Its
diagnostic-only observer is limited to fixed list-status enums, an error class,
bounded row count, target-node present/visible booleans, the selected
package-owned scroll container, the last action container, and bounded scroll-action
count from the real UI. The state set is bounded and ordered by last sighting,
not a complete transition trace. Row count and target presence refer only to
observed accessibility nodes; absence does not prove an empty Hub list. It does not export message or proof content, view trees, IDs, credentials,
or native / Session method calls. It preserves the existing forward-only
20-second UI behavior; it does not satisfy the response visibility or consent
gate.

### Offline verification

The commands below ran in the immutable cached build image
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`
with `--pull=never --network=none`, read-only source mounts and no credentials.
The exact Docker argv, source hashes, log hashes and timings are in each receipt.
Docker data root was independently checked as `/gpu1-share/data/docker-root`.

| Command | Result / exit code | Receipt under V | Receipt SHA-256 |
|---|---|---|---|
| `python3 V/focused-check.private.py js-tests` | **PASS / 0**, 17 tests | `js-tests.receipt.redacted.json` | `3be488eed909d85acc4082144f97bc53b27645f510185c1843ace22c2287393a` |
| `python3 V/focused-check.private.py python-tests` | **PASS / 0**, 23 tests | `python-tests.receipt.redacted.json` | `eea12d9b9bdd284d1f0e51846e78b4fa75879b7c880f96545339235ab2994ffc` |
| `python3 V/focused-check.private.py typescript` | **PASS / 0** | `typescript.receipt.redacted.json` | `57fa2dfe2ce8613663252e90bfc8bccdc430201fd257dcf08f243c857a0a7c2a` |
| `python3 V/focused-check.private.py eslint` | **PASS / 0** | `eslint.receipt.redacted.json` | `89b4a837f86846d1a3feae24bb48f554bc22e942bf14636e7830356b16233686` |
| `python3 V/focused-check.private.py kotlin-regression` | **PASS / 0**, 15 synthetic cases; compile and JVM exit 0 | `kotlin-regression.receipt.redacted.json` | `63642874a264124c3897509ddbb9f6847b3eaedb918d6b81358ccdd5de760dbb` |

`V` in the commands denotes the absolute cache path above. The Kotlin tests
compile the existing six viewport cases and nine new UI observation cases using
cached compiler artifacts. They do not run Android, use a Hub, or verify native
model consumption. No dependency or build image changed.

The successor retains the real visible-text assertion, PROPOSED assertion,
Alert scope, proof, Guard, expiry, packet recovery and bilateral checks. Its
list record always says `OBSERVED`, even if the text wait matches. The driver
captures and strictly validates this record on both successful and failed UI
runs; it cannot turn a failed JUnit run into acceptance. Counts are clipped at
100 observed rows and 80 action attempts with explicit truncation flags. A null
last action return means the action result was not observed. Missing app roots
clear current fields to unknown while last-seen state remains explicitly historical.

At this source checkpoint the post-commit APK build and fresh live acceptance
are **NOT_RUN**. External build, 26-source closure and delivery receipts under V
will bind the exact clean checkpoint commit and one new app/test APK pair.
Root owns the next fresh launch; no prior operation, signature or fixture was
replayed here. Physical Android, native Worker and public HTTPS are **NOT_RUN**.

## Evidence index

Only safe status fields, booleans, phase names, and evidence hashes are recorded;
private proof bodies, messages, IDs, and raw JUnit contents are omitted.

| Evidence | Path | SHA-256 |
|---|---|---|
| Android artifact attribution | `E/android-artifacts.json` | `aef20e62aa25f2ec0c32f6bef69c6723ad24b95fb8ae84535ecf442ebc0c8ef8` |
| Android runtime | `E/android-runtime.redacted.json` | `dcf9b9ba32bb69290cdb8d5ba71cf062ec776143b0c0c82d9cd7df56053ed30d` |
| SOURCE enrollment/capabilities | `E/link-v164/receipt-source-enrollSourceOwnerDeviceGrantAndVerifyFreshCapabilities-994e561c725f.private.json` | `994e561c725f93450f1a9ef22005f13b7c2965b1d06848cf655ca2f220663956` |
| SOURCE independent pins | `E/link-v164/receipt-source-confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval-ab1651ff398c.private.json` | `ab1651ff398cd6c6f7a3b69e21acb8f0d4e8f95c88e0235be91f2f472f7b2051` |
| SOURCE KEY fresh status | `E/link-v164/receipt-source-submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus-a982dce3b8de.private.json` | `a982dce3b8de46729e155b06a3c1d620d24317e5c58ba7bbbf898057650f65c9` |
| SOURCE policy fresh status | `E/link-v164/receipt-source-submitsHostSignedPolicyProofAndRevalidatesFreshV164Status-36a705b77a58.private.json` | `36a705b77a58d8ca49bc6190d5a19bac6741a5ebbd488f39d73a48384cce18d4` |
| TARGET enrollment/capabilities | `E/link-v164/receipt-target-enrollTargetOwnerDeviceGrantAndVerifyFreshCapabilities-cc658d74e5cd.private.json` | `cc658d74e5cde44585ff5eab4dbdce8c8dafa56b956fc6d40f6ffe345a1f444e` |
| TARGET independent pins | `E/link-v164/receipt-target-confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval-1122b13c93df.private.json` | `1122b13c93dfe7902647b39cb577d953f2c0424316019ae62b3ec400c42bda0f` |
| Target passive progress | `O/target-key-rn.phone-ui-submit-progress.redacted.json` | `40887a76068c8e9f675743d0f7dad03ddaf6dce57b7c1a3c95b46ac9b63a3dfe` |
| Target UI result | `O/target-key-rn.result.redacted.json` | `973cea26bd52a62ca9a6d68d4d3b714b86f947d027ad3ac5194f85d0fbeaff11` |
| Target JUnit log (hash only) | `O/target-key-rn.instrumentation.private.log` | `7790b002af07ba156db8c7568c944a2fb7e53dea0f34236d4c3194ab429f3683` |
| Canonical launcher terminal | `L/terminal.private.json` | `6289f96240f11c0d8f6aeb0aacebe96e4e1728fe4047db7eca533f2bef288577` |
| Android teardown | `E/android-teardown.redacted.json` | `5709d7ea42ef7eba46b08f4d9c8bdb6647ca9d035e18a8c542282a3ebdab8437` |
| Emulator absence check | `E/emulator-absence-check.redacted.json` | `446298acf46460aba6f77186d637183371180c00c97a7c595d1041c61ca172ab` |
