# Client-Control v1.6.5: fixed Client validation

## Scope and authority

This record separates the original offline APK preparation from Root's later
joint11 Android emulator RPC recovery run and independent cleanup review.
The docs-only closeout executes no tests, build, model or runtime operation
and authorizes no push, merge or production release. Immutable APK production
and tested host source retain their original external seals.

Evidence root:
`/gpu1-share/data/cicada-client/v165-c6887f4-client-preparation-20261010`.
`DELIVERY.NONAUTH.json` is the final hash-only handoff index; it binds the actual
clean Client commit, complete input inventory, test receipts, APK bytes,
producer command and coordination template. It is not an Owner grant or GO.

## Immutable Core target

| Item | Exact value |
| --- | --- |
| Core commit | `c6887f46c8412e648b8e8e68da371acd80e0b87e` |
| Source dirty | `false` |
| Contract | `client-hub-v1.6.5` |
| Versions | wire `1`, catalog operations `55`, schema `59`, software `0.0.2` |
| Shipping Hub image | `sha256:b7bc42678adf9ab44df2a3c51732b2956d668dd7745a93ec3c2a0387d3fc07c2` |
| Current test image | `sha256:fa314f2b3f54d269bca963edae675fa0142d0d2bbf833c24170aafaba25c4477` |
| Source fingerprint | `cc4ae9207a790c30e9b702c378d9a699bfe95f56e80b5ccfe3b748a6aefaf1ef` |
| Catalog SHA-256 | `a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9` |
| Protocol bundle SHA-256 | `37759169d0f776ab318a2cced01ac0ce557fba446980a5b3d112598dc72f50a4` |
| Delivery manifest SHA-256 | `f159869f38d8a7a82525a6da4fdcd96de1e43213d4c3d5023b77a15b8758e911` |
| Dispatch receipt SHA-256 | `92412d982d9347a179112df929b1642c54d5710f3c334d3611e98fd0d4b694fa` |
| Build metadata SHA-256 | `3a18caeebb5cba467e44b2bb319a92f49054ccd5771cc95603784ec5d2500b43` |
| Core binary SHA-256 / bytes | `f6b3e88beca01a837c744458d205f330ffb2e1dd4a6580b04faf863d91082d4f` / `23511200` |

The imported snapshot is `contracts/client-hub-v1.6.5-c6887f4`: exactly 25
regular archive entries, comprising the manifest and its 24 size/hash-verified
payloads. The separately formatted delivery manifest and embedded contract
manifest have identical parsed fields and different raw hashes. This is
recorded explicitly; one cannot substitute their raw digests.

Actual Docker IDs and revision/dirty/fingerprint/catalog labels matched the
pins. The independent Client verifier reproduced the inventory and v4 source
fingerprints, verified all 957 Git tree/index objects and verified the pinned
inventory producer's source without executing it. The exact supported scope
now includes `LICENSE`; historical scope remains independently supported.
Omission, modification and scope downgrade are rejected. Current Core worktree
mode verification and the exported image tar hash were not run; immutable
image IDs and build metadata were checked instead.

## Client changes

The shared TypeScript and Native contract pins now require v1.6.5 and its exact
catalog. The existing Link instrumentation also requires c6887's shipping Hub
and source fingerprint. UI, local STT, generic RPC restrictions, cryptographic
formats, pending packets, sequence counters and recovery fences are preserved.

New Client policy previews always send the independently selected `owner_key_id`.
Signing requires the correlated `signing_owner_key` tuple with exact Owner/key,
complete independently pinned ML-KEM/ML-DSA identity, ACTIVE state and a
canonical positive int64 version. The existing optional server field supports
legacy callers; absence grants this Client no signing authority. Fresh preview
and revocation checks remain necessary at submit/recovery. A registered policy
signer needs no accepted Link KEY grant. KEY verification remains unchanged.

The public policy vector is byte-identical to its earlier version and lacks
the new tuple. Kotlin tests construct the tuple in memory and independently
exercise proof generation/verification and failure predicates. This is not a
new published cross-language response vector or an Android acceptance claim.

## Actual offline commands and results

All container commands use immutable builder
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`,
`--network none`, the server UID/GID and caches below
`/gpu1-share/data/cicada-client`. Docker root was verified as
`/gpu1-share/data/docker-root`. Full argv, inputs, logs, exits and durations
are in each stage's `receipt.NONAUTH.json` below the evidence root.

| Stage | Actual command via the evidence-root `run-offline.py` | Exit | Result |
| --- | --- | --- | --- |
| Contract and source-scope regressions | `python3 run-offline.py python-green` | `0` | **PASS**, checker + 34 Python tests |
| Independent Core inventory | `python3 run-offline.py inventory` | `0` | **PASS**, 957 rows and pinned helper |
| UI authorization and operation policy | `python3 run-offline.py frontend` | `0 / 0` | **PASS**, 72 Node tests and `tsc --noEmit` |
| Pure Kotlin vectors and policy | `python3 run-offline.py kotlin-green` | `0` | **PASS**, 38 tests, no failures/errors/skips |
| Fresh APK pair | `python3 run-offline.py apk` | Producer receipt | Actual bytes and producer outcome in final delivery index |

Kotlin scope: five wire tests (both directions, canonical AAD, signatures,
packet parsing and tamper refusal), three Endpoint/manifest tests and thirty
policy tests. Android runner/asset access is adapted only in external host
copies; cryptographic assertions are unchanged. Policy negatives include
missing/null/extra signer fields, wrong Owner/key/full identity, stale or
non-ACTIVE authority, noncanonical/zero/negative/bool/overflow versions,
fresh version changes, scope/side/expiry/qualification failures and duplicate
JSON fields. Peer proof verification does not imply bilateral acceptance.

Preserved failed attempts:

- `python/receipt.NONAUTH.json`: test environment lacked the declared temp
  directory and server global Git configuration. The corrected run mounts the
  actual global configuration read-only and uses a private test temp directory.
- `kotlin/receipt.NONAUTH.json`: 39 tests attempted; one existing Group Owner
  proof test cannot call `android.util.Base64` in a host JVM. The scoped green
  run excludes that platform-dependent test. Its Android execution is **NOT_RUN**.
- The first delivery checker incorrectly required raw equality between the
  differently formatted manifest files. Their independent pinned hashes and
  parsed equality passed; the failed assumption is retained in the receipt.

Tests ran on explicitly recorded working-tree inputs based on e3d26f8 before
the combined checkpoint. Final delivery checks join those tested input bytes
to the clean commit. The APK producer runs after that commit and records its
actual clean/dirty state and input inventory; it does not inherit an old APK's
source attribution.

## Runtime results and Root coordination

### Joint11 terminal Android recovery and independent cleanup

Root executed `v164-e2a1908-joint11-20261010` once, with no model calls.
The tested clean host commit is
`3cfb3cf08f1f9fa93b58bd31959b8f901ef9f4c0`; its 631-input inventory SHA-256
is `54cf1bea86b3adf164dd1672f6a944e500b56a336b199a1e97605f8f3bbf9e56`.
The 12-driver map SHA-256 is
`486f50a684cc4bc2dd0acd39b9c5b547732406e3741b7fee075de84cf4269612`.
Its immutable preparation index is
`/gpu1-share/data/cicada-client/v165-c6887f4-joint11-consumer-20261010/DELIVERY.NONAUTH.json`,
SHA-256 `b8c576d682be2b8f4bfffb43419cfe8261a9ae7fa1a51fb9dc0d95554987990f`.

APK producer remains clean `1151b06e04b172de9c7b5989ffec1318e58bf862`,
with source-input SHA-256
`4e80a1f0a4e7741fe4a2f3da82dddc85bb1f978f73a6534977a321ec32af2558`.
App SHA-256 is `e5707b6a5a91a45eca8285970e646408cf34d05cf246e1bcd4c9f1af9c4a3745`;
test SHA-256 is `7638c1ed4f3a3d6f549b78e64a1802612de59f4b6359bd9cc1795ce61065ca29`.
This documentation checkpoint does not rebuild, reseal or relabel those inputs.

| Case | Android operation | Fault mode | Android RPC recovery | External Go business reconciliation | Android status read |
| --- | --- | --- | --- | --- | --- |
| 0 | `link.key_grant` | response-loss | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 1 | `link.key_grant` | processing | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 2 | `link.key_grant` | uncertain | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 3 | `link.key_grant` | legacy | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 4 | `link.review_policy_grant` | response-loss | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 5 | `link.review_policy_grant` | processing | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 6 | `link.review_policy_grant` | uncertain | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |
| 7 | `link.review_policy_grant` | legacy | **PASS** | **PASS**, separately reconciled | **NOT_RUN** |

All Client cases finish at `RECONCILED`, with business outcome
`SEPARATELY_RECONCILED`. Core records
`SEPARATELY_RECONCILED_EXTERNAL_GO` for all eight. Each case performed real
TARGET-first/SOURCE-last Android enrollment; no SOURCE return switch was
performed through recovery and finish. Core's owned restarts at cases 2 and
6 both **PASS**, against the exact shipping image.

KEY reconciliation uses the independent Go TARGET encrypted Owner session.
NONE reconciliation has the exact attribution
`CORE_PARENT_MIXED_DIRECT_E2EE_HEAD_AND_DB_READONLY_CANDIDATE`: encrypted
HEAD/preview reads and a separate Core read-only candidate witness. The
one-sided candidate remains distinct from the public current HEAD. This
does not prove bilateral acceptance or an Android pending-candidate API;
Client neither reads the database nor claims Android status-read coverage.
Native Worker/runtime, physical Android and public HTTPS are **NOT_RUN**.

The actual Root command is recorded in the outer receipt. Let `P` denote
`/home/zyf/CICADA/.cicada-data/architecture-v2-completion/client-delivery-v165-c6887f4-20261010/joint-preparation`.
The following is its recorded invocation, not a reusable authorization:

```sh
timeout --signal=TERM --kill-after=15s 3630s /usr/bin/python3 -B "$P/joint-parent-v7.py" \
  --template "$P/joint-template.V7.JOINT11.private.json" \
  --template-sha256 b48350cb03f2c83cecffe52c4e7e22aa516a95aa0fc05fcb35375fbdc52a83eb \
  --core-config "$P/core-config.V7.JOINT11.private.json" \
  --core-config-sha256 c6acc231eebea338d8811ea41099636b47842e85be265e9e9aff8475161ad592 \
  --master-go "$P/ROOT-JOINT11-MASTER-GO.private.json" \
  --master-go-sha256 dda6381f189d297e7859530ea3a1d2ca37c420e2eb816750256fd114edbe9d7f \
  --go
```

Outer exit is `0`, elapsed `513.1198035785928` seconds. Parent reports
`PASS_JOINT_ANDROID_EIGHT_CASE_ONLY` in `512.1916142394766` seconds; Core
reports `PASS_CORE_JOINT_AND_EXTERNAL_GO_FIXTURE_ONLY` in `511.22856881283224`
seconds. The distinct 82 Parent events and 65 Core controls, including unique
final case7 close ACK, pass the independent terminal review. Master state is
`USED_CLOSED_NO_REUSE`; it must not authorize any subsequent run.

| Evidence | Path relative to `P`, except Client result | Actual SHA-256 |
| --- | --- | --- |
| Parent | `parent-run-evidence-2d0049a266db2c99073cf500ddb3c6cf314402e36b7b2f2f3a25641c9fdae752/result.NONAUTH.json` | `672a23d7050068a97cd7601f6b9726e4e802014c6be5708a8ea4c0961ee7d2f8` |
| Core | `joint-run-joint11-20261010/result.json` | `b291e817a72388dbf26e6f92860a15d6e8b3982d189fa4c3385018ef36cef943` |
| Outer | `ROOT-JOINT11-OUTER.NONAUTH.json` | `b7b867a2570189d3970cfd47ca72ea0649821d8659313ebc56a074df63926f7b` |
| Client | `/gpu1-share/data/cicada-client/v165-joint11-root-final-20261010/result.redacted.json` | `5954537dfd7e0631e03747a29fc61f421fed60c76e334a828a5771cef22cec65` |
| Independent cleanup | `ROOT-JOINT11-CLEANUP-INDEPENDENT.NONAUTH.json` | `0a7dfc5b4546842a808720f6e02c97052c5570bc025f6f8e2591d6ea420a0740` |

All five raw hashes were independently matched during this docs-only update.
Client result contains eight **PASS** cases and cleanup **PASS**. Root's
`PASS_SCOPED_POSTCHECK` confirms exact Hub ID/name and recorded Android ID
absent, scratch absent, all 188 Client and 59 Parent recorded process groups
closed, tested Client source clean, and unchanged Core source and six resident
snapshots. These are scoped checks of the owned run, not a global process audit.

Historical joint8 remains overall **FAIL** before enrollment; joint9 remains
overall **FAIL** at stale reconcile delivery guards after partial case0.
Joint10 retains its eight scoped case passes and overall **FAIL** at final
`CONTROL_COUNT`, with no final ACK. Original receipts, source attribution and
closed Masters remain unchanged. Joint11 establishes this eight-case Android
RPC recovery slice; it does not establish general product, Native or release
acceptance. No tests, model calls or build were rerun for this closeout.

### Historical offline preparation status

| Item at the original preparation checkpoint | Status |
| --- | --- |
| New shipping Hub encrypted `session.capabilities` | **NOT_RUN** |
| Eight Android KEY/NONE recovery cases | **NOT_RUN** |
| New fresh NONE preparation/signing on Android | **NOT_RUN** |
| Independent opposite-Owner reconciliation | **NOT_RUN** |
| Physical Android / public HTTPS / iOS | **NOT_RUN** |
| Current-source helper/Parent freeze | **PASS**, offline source/hash verification only |

Core's five-event source-scoped gate used its separately built ae9d4a0 Hub,
not shipping b7bc. Its PASS cannot be reported as Android PASS or as a runtime
test of this exact shipping image. Its default gate did not test the fresh
NONE signer predicate. Joint7's four KEY passes retain old d8855e3/e2a/APK
attribution; NONE-response-loss remains failed/unknown and the other three
NONE cases remain unrun in that historical batch.

## Historical joint8 current-source host consumer

The actual V5 delivery is pinned under Core's
`client-delivery-v165-c6887f4-20261010/joint-preparation`. Its legacy fixture
namespace stays independent from product v1.6.5. The final Parent freeze
binds the current compiled-source references and Root APK endorsement; the
compiled-readiness record retains the pre-endorsement adapter's source
attribution. Materialization changed only its APK endorsement constant.

| Artifact | SHA-256 |
| --- | --- |
| `joint-parent-v5.py` | `1c6370701ab793b390e364d56ac18a8cb60cf4ca4e1b568e56fafab1e3880b01` |
| `joint-adapter-parent-ready-v5.py` | `211ec899ff9ba62ed56d66b13d0de8cd56c8aafd232e20be8ed14c76a10482d5` |
| `JOINT-PARENT-V5-INTERFACE.NONAUTH.md` | `eafb6ca987a5368ae9d04a9bf17d43fe15caaa36896cec4be3a9445ab2aa9e0d` |
| `JOINT-PARENT-V5-FREEZE.NONAUTH.json` | `33cc0d315f876d5da3187ee17548b1457b0a0af0ac3e816f6cbc6577dba50eb4` |
| `JOINT-PARENT-V5-FINAL-QA.NONAUTH.json` | `fd96eb975fbf969ec88cf3f9604769fa7fa52dfb408315a897144d3abd38f3b3` |
| Root-endorsed APK pins | `fae3c7e442335369af39f0a35bc2dac95ae3cab591a2b2597b9d45f053cb03be` |
| Root compiled-helper review | `3c4f5795335c18e56adab3d96d39aec24b6e93e1c88e5ee820b2079403d163c8` |
| Base compiler receipt | `d7ef12062ee1523faf19d7132f8d50fa28209198fc64c013c48adbb97566a256` |
| Flat-signer compiler receipt | `f11ece4f9d49c33bd426b03624f57ba2e4b13a9d3193313d0130af5b1ddf4f32` |
| Reconcile binary | `e0fddfb7580542e93b4a8ff93eabf9a39903f787b6034bce6cc7efb3e748c3d7` |
| Reconcile compiler receipt | `728bcdc39eb25189c4ac465bec5434d2847e0d1ac308195eb1a692ff1d4f0197` |

Consumer evidence root:
`/gpu1-share/data/cicada-client/v165-c6887f4-joint8-consumer-20261010`.
The final `DELIVERY.NONAUTH.json` seals clean host source, all 12 actual drivers,
full input inventory, Root Parent template and argv; it is not a Master or Grant.
APK production remains clean `1151b06e04b172de9c7b5989ffec1318e58bf862`, with app
SHA-256 `e5707b6a5a91a45eca8285970e646408cf34d05cf246e1bcd4c9f1af9c4a3745` and
test SHA-256 `7638c1ed4f3a3d6f549b78e64a1802612de59f4b6359bd9cc1795ce61065ca29`.
Current host source is separately attributed; no second APK build is implied.

Commands use the same immutable builder, `--network none`, a read-only source
mount and finite 180-second stage timeout. Exact argv, tested input hashes,
logs, elapsed time and owned-container absence are recorded per stage.

| Command from consumer evidence root | Exit | Actual scope |
| --- | --- | --- |
| `python3 run-scoped.py historical-red` | `0` | Expected old-source `READY_RUNNER` rejection |
| `python3 run-scoped.py unit` | `1` | 38 tests attempted; one stale reconcile-pin assertion, preserved |
| `python3 run-scoped.py unit-green` | `0` | 38 relevant Python tests **PASS** |
| `python3 run-scoped.py guards` | `0` | 14 actual source/hash checks **PASS** |

Green scope includes the exact V5 seven-file map, QA joins, Root preparation
references, current runner, stale V4/APK-HOLD refusal, strict loopback URL,
current clean APK provenance, ordered eight-case plan and bounded supervisor.
The actual guard pass hashes all five binaries, joins current compiler receipts
and endorsement, and verifies all 957 fixed Core Git inputs/modes. It executes
no Core code, reads no database and records no proof body or credential.
No old 73ec image, 54d binary or compiler receipt is accepted as current evidence.
New encrypted `session.capabilities` and every Android case remain **NOT_RUN**.

Root alone supplies the final source-bound config and fresh Master for reserved
batch `v164-e2a1908-joint8-20261010`. Templates have no GO, approval or expiry.

Retain the original 82 requests and 25/11 callback fields. Each of eight cases
creates real TARGET Android enrollment first, SOURCE last, then keeps SOURCE
active through signing/capture/original recovery/finish. Independent Go TARGET
readonly evidence remains separately attributed. Keep 3600s outer/360s case
limits and owned restarts at case indices 2 and 6. Root owns keys, Master,
Hub/emulator lifecycle, network-none carrier and cleanup. Ordinary cross-user
messages remain closed while `external_thread_links=false`.
