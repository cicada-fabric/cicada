# Client-Control v1.6.5: fixed delivery and offline Client validation

## Scope and authority

This checkpoint updates the Client to Root's clean v1.6.5 export and prepares
a fresh Android app/test APK pair. It authorizes no online run, Hub lifecycle,
model call, push, merge or production deployment. The immutable APK producer
and final source seal are external records to avoid a self-referential Git
commit or artifact hash.

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

| Item | Status |
| --- | --- |
| New shipping Hub encrypted `session.capabilities` | **NOT_RUN** |
| Eight Android KEY/NONE recovery cases | **NOT_RUN** |
| New fresh NONE preparation/signing on Android | **NOT_RUN** |
| Independent opposite-Owner reconciliation | **NOT_RUN** |
| Physical Android / public HTTPS / iOS | **NOT_RUN** |
| Current-source helper/Parent freeze | **BLOCKED**, awaiting Root delivery |

Core's five-event source-scoped gate used its separately built ae9d4a0 Hub,
not shipping b7bc. Its PASS cannot be reported as Android PASS or as a runtime
test of this exact shipping image. Its default gate did not test the fresh
NONE signer predicate. Joint7's four KEY passes retain old d8855e3/e2a/APK
attribution; NONE-response-loss remains failed/unknown and the other three
NONE cases remain unrun in that historical batch.

Root must provide fresh source/image/binary/compiler pins for the helper,
fault proxy and reconciliation tool, plus the compatible Parent source set.
Historical host drivers are inventoried as historical bytes and remain
fail closed on their old pins. No old 73ec build image, 54d reconcile binary
or compiler receipt is accepted as v1.6.5 evidence. The new argv template
contains only placeholders and **NOT_GO**; it cannot authorize a run.

Retain the original 82 requests and 25/11 callback fields. Each of eight cases
creates real TARGET Android enrollment first, SOURCE last, then keeps SOURCE
active through signing/capture/original recovery/finish. Independent Go TARGET
readonly evidence remains separately attributed. Keep 3600s outer/360s case
limits and owned restarts at case indices 2 and 6. Root owns keys, Master,
Hub/emulator lifecycle, network-none carrier and cleanup. Ordinary cross-user
messages remain closed while `external_thread_links=false`.
