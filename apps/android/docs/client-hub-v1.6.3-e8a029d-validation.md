# Client-Control v1.6.3 candidate provenance and validation

**Record date:** 2026-10-02

**Core release:** `e8a029d79bbdddb75ea376afa76e62a5c8444f59`

**Contract:** `client-hub-v1.6.3`, wire version 1

**Client validation scope:** public contract import and offline host-JVM candidate tests only

## Result summary

The v1.6.3 public contract bundle and immutable Core image identities passed
provenance checks and were imported into the versioned Client contract
directory. Root's retained offline Docker host-JVM run passed all 16 selected
Kotlin tests for the Link manifest verifier and Link review-policy consent
candidate. Those tests validate candidate code and supplied test inputs; they
are not Android instrumentation, APK, encrypted Hub, native-model, physical
device, or HTTPS acceptance.

The accepted Android baseline remains Core `144e079` / Client-Control v1.6.1.
The imported catalog describes 55 server operations; the current Android
operation policy remains 39 implemented and 16 closed. No v1.6.3 runtime pin
or APK was produced. See the separate [v1.6.1 acceptance record](client-hub-v1.6.1-144e079-validation.md)
for evidence attributed to that earlier fixed target; those results do not
transfer to v1.6.3.

| Gate | Result | Attribution |
|---|---|---|
| Artifact index, archive, manifest, clean-source blob comparison, public payloads, independent 835-entry source inventory | **PASS** | Read-only provenance verification for the exact e8a029d release; inventory scope and mode caveat below |
| Immutable Hub and interop image identity/labels | **PASS** | Read-only `docker image inspect`; selected identity and labels only |
| Core clean-image gate | **PASS, producer-recorded** | Release artifact index; not rerun as Client acceptance |
| Link candidate Kotlin host-JVM unit tests | **PASS** | Offline development container; 16 tests, 0 failures/errors/skips |
| v1.6.3 encrypted `session.capabilities` and `/v2/client/rpc` runtime | **NOT_RUN** | No Client session was connected to this Core candidate |
| v1.6.3 Android build or new APK | **NOT_RUN** | Candidate test receipt records `candidate_apk: NOT_BUILT` |
| Android emulator/instrumentation, native Node/model execution | **NOT_RUN** | Host-JVM results do not establish device or native behavior |
| Physical Android and public HTTPS | **NOT_RUN** | No device or public endpoint was tested |

## Immutable Core provenance and contract import

The independent artifact index is
`/home/zyf/CICADA/.cicada-data/final-std-e8a029d-20261002/artifact-index.json`,
SHA-256
`3cd74300c3ed53cd68f914781f3df2e913e27079a6271ebbb697854f50a5aec5`.
It records the full clean source commit
`e8a029d79bbdddb75ea376afa76e62a5c8444f59`, source fingerprint
`72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4`,
catalog SHA-256
`5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`,
wire version 1, Hub schema version 55, and 55 catalog operations. The release
index and bundle manifest both mark the released source clean. The release
provenance compares the bundle payloads to Git blobs at the full e8a029d
commit; this is not a claim about the cleanliness of a separate working tree.

### Independent source-inventory reproduction

A separate read-only reproduction verified the pinned build inventory against
the exact Core commit. It matched all 835 scoped inventory paths to the full
Git tree, matched each inventory row's Git blob OID and Git mode to that tree,
and read all 835 immutable Git blobs to verify size and SHA-256. It independently
recomputed the v4 source fingerprint and canonical inventory digest; all
835 entries were indexed, with no missing paths. The reproduced source
fingerprint is `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4`,
the inventory digest is
`ff03905f082927a634b6a7cba75dfddcf7e713a4d0766659e979ea757f8eab0d`, and the
catalog digest is
`5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`. The
source-before and source-after snapshots both match the pinned build inventory.

The reproduction receipt is
`/gpu1-share/data/cicada-client/v163-e8a029d-20261002/provenance/independent-source-inventory.redacted.json`,
SHA-256
`0d35d73d5a205c499c916777b1c0b2fd414ef2ebec201042fe0c91d15c2e3903`. Its
embedded Python 3 standard-library reproduction returned `PASS`; all five
recorded Git commands (`rev-parse`, `cat-file -t`, `ls-tree`,
`cat-file --batch`, and `show` for the pinned inventory implementation) exited
`0`.

The mode checks have distinct scopes. The 835 source rows' recorded `git_index`
OIDs and Git modes (`100644`, `100755`, or symlink mode `120000`) were compared
with the exact commit tree. The v4 fingerprint used each row's recorded `raw_mode`,
normalized with `stat.S_IMODE` and encoded as four-byte big-endian data. This
receipt does **not** claim to have re-read the current Core worktree's raw
permission bits or checked its worktree status; the pinned commit and recorded
build inventory are the sources for this reproduction. The archive member
mode check above is a separate check of the imported protocol bundle.

The protocol archive is
`/home/zyf/CICADA/.cicada-data/final-std-e8a029d-20261002/contract-bundle/client-hub-d365bc775189cd10ac986045304af4246a313c01921732f8f976a81495141276.tar.gz`,
SHA-256
`d365bc775189cd10ac986045304af4246a313c01921732f8f976a81495141276`.
The archive has 24 regular-file members, including `manifest.json`, and 23
public payload files totaling 829,237 bytes. The manifest SHA-256 is
`d76f6065b8fb5d8a3bdf13754e73edeff2484a4ee83fd03c8802cc8f75a3ab6b`.
The bounded check verified canonical relative paths, no duplicate members or
links, mode `0644`, no PAX metadata, exact payload sizes/digests, full source
revision, `source_dirty=false`, and byte equality of all 23 payloads with the
e8a029d Git blobs. The included keys are explicitly public synthetic/test-only
fixtures, with warnings not to deploy them; no real deployment credential or
production private key was imported.

The exact archive members are imported under
[`contracts/client-hub-v1.6.3-e8a029d`](../contracts/client-hub-v1.6.3-e8a029d/manifest.json).
All 24 files, including the manifest, compare byte-for-byte with archive
members; payload hashes match the manifest. Import and final tree comparison
both exited `0`. The private redacted provenance receipt is
`/gpu1-share/data/cicada-client/v163-e8a029d-20261002/provenance/client-hub-v1.6.3-provenance.json`,
SHA-256
`3fad7774e29c286a11c2a706dbd5498c7274a17be41d6aa0fb591b0865770dff`;
the task and provenance directories are mode `0700`, and the receipt is mode
`0600`.

### Immutable image evidence

| Role | Immutable image ID | Source fingerprint | Catalog SHA-256 | Dirty label |
|---|---|---|---|---|
| Hub | `sha256:b048442b6a9bb12f441e72ed60de2a0c31b0757343c09dcaa25cea5eb95e595e` | `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` | `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf` | `false` |
| Interop runner | `sha256:5bfffe0611103eaa772c0aa846246d4eedfcf8c7d5a58182acef7a5c432950e3` | `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` | `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf` | `false` |

Both images report revision `e8a029d79bbdddb75ea376afa76e62a5c8444f59` and
their exact digest RepoDigest. The recorded read-only commands exited `0`:

```sh
docker image inspect sha256:b048442b6a9bb12f441e72ed60de2a0c31b0757343c09dcaa25cea5eb95e595e --format '{{.Id}}|{{json .Config.Labels}}'
docker image inspect sha256:5bfffe0611103eaa772c0aa846246d4eedfcf8c7d5a58182acef7a5c432950e3 --format '{{.Id}}|{{json .Config.Labels}}'
```

Only image identity and public labels were inspected; `.Config.Env` was not
read. The artifact index records the Core clean disposable-image gate as
`PASS`, including exact image identity/evidence checks. This is Core evidence,
not Android acceptance. The Client verification did not execute Core fixtures,
Hub, or Node.

The exact bundle/import verifier, payload-to-Git comparison, selected image
labels, import result, and exit codes are retained in the private provenance
receipt linked above. The artifact index records archive export and verification
exit `0`; the Client-side bounded verifier/import and final tree comparison
also exited `0`.

## Earlier offline Kotlin candidate verification

Root ran the candidate tests in the offline development container
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
The final command was:

```sh
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace \
  -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules \
  -w /workspace \
  -e GRADLE_USER_HOME=/gradle-cache \
  -v /gpu1-share/data/cicada-client/gradle-cache:/gradle-cache \
  -v /gpu1-share/data/cicada-client/android-home:/home/gradle/.android \
  -v /gpu1-share/data/cicada-client/link-consent-candidate-20261002:/out \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  gradle --offline --no-daemon --project-dir /workspace/android \
  -I /out/kotlin-host.init.gradle :app:testDebugUnitTest \
  --tests ai.cicada.client.hub.LinkKeyManifestVerifierTest \
  --tests ai.cicada.client.hub.LinkReviewPolicyConsentValidationTest
```

The final run exited `0` in 26.28 seconds. JUnit reports 16 tests: 7 in
`LinkKeyManifestVerifierTest` and 9 in `LinkReviewPolicyConsentValidationTest`,
with zero failures, errors, or skipped tests. The final test summary records
`PASS` and `candidate_apk=NOT_BUILT`. The source fingerprint before and after
the run was `cf709ed5bfd8e77059a6c4c73a7c2e20902f3c777baf597d58a02b5be19e09e9`
(128 files); tested inputs were unchanged at
`e583707b0a92050217b5ff3a977c17e412bf24f0bd2666a47371775dc8abc4a1`
(101 files).

Coverage includes positive verification of the public synthetic bilateral
Link key-proof vector and published Owner policy proof under independently
supplied trusted-key/expected-authority inputs; Link/contract/digest/version/
side checks; Go-compatible policy digest escaping; preview/policy equality and
head CAS; fresh Link/reviewer authority revalidation before using a cached
preview; duplicate JSON keys, unknown preview fields, unnormalized reviewer
order, stale proof and changed trust/status rejection. These are pure JVM
checks over supplied fixture or authority values. For Link key-grant
validation, the fresh encrypted `link.key_manifest` is the contract-authoritative
single-transaction Store snapshot for both Link sides. Its `scope_snapshot`
revisions correspond to the current Store read and its sides carry current
binding and Endpoint candidate/attestation material; `link.key_grants` carries
the current Owner proof evidence. A separate `link.list` or topology authority
read is not required for that Link scope. Native integration still has to parse
the authenticated manifest, independently verify Endpoint and Owner evidence,
and correlate it with status/grant data. The manifest does not establish an
independent trust root for a peer Owner or supply the distinct `link.review`
permission evidence required for policy reviewers. No live Hub exchange was
run here.

The final retained evidence is:

| Evidence | Path | SHA-256 |
|---|---|---|
| Final command/result receipt | `/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final/kotlin-host.receipt.json` | `ffcaec8de5d0b284691977ee97d149dbb86303fff24ec115cee435021dfd82e3` |
| Final Gradle log | `/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final/kotlin-host.log` | `0ecfa692091ddfe14103eb5ee287d434fa545ab7df2a72db3488e860c65dc853` |
| Redacted suite summary | `/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final/kotlin-test-summary.redacted.json` | `303a7b6c6dff35f6e0b676d7a48112a0ccd3bb3faa168fc603091101c9697a74` |
| Manifest verifier JUnit XML (7 tests) | `/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final/TEST-ai.cicada.client.hub.LinkKeyManifestVerifierTest.xml` | `3c407da6f89032f3c370fa99db91e1d357403bb9418a2f7939218da8b335f1ea` |
| Policy consent JUnit XML (9 tests) | `/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final/TEST-ai.cicada.client.hub.LinkReviewPolicyConsentValidationTest.xml` | `a8883581192979e8f2ef3666690fd87cf2c75cab705944f8458178d956ae95a5` |

The receipt binds the selected Kotlin test sources: `LinkKeyManifestVerifierTest.kt`
SHA-256 `338c50de24204dd21ad60cea2a07d930b650fb1ae6fdbf21e8b53f816ddfc8a9`;
`LinkReviewPolicyConsentValidationTest.kt` SHA-256
`37675d004c36c71ff40a5d77298bad4b3addd76e06dfcd45c3a708cf8b572a7c`.

Earlier attempts remain preserved rather than replaced: `checks/kotlin-host.receipt.json`
(SHA-256 `84bd1c375032099aa5b1b26e684fe56c5056f1ebcd2231491c48490ecb968229`)
exited `1` on a test-source `replaceFirst` compile error;
`checks-corrected/kotlin-host.receipt.json` (SHA-256
`f19ea2fcd69812a9e29babeffc2228e07c5eaf8ac499ef407c6b63ea86113137`)
exited `1` on the Go-compatible policy digest escaping assertion. The final
`checks-final` receipt above is the corrected pass. None of these commands
built an APK or ran Android instrumentation.

## Contract delta and Android/runtime boundary

Compared with the accepted v1.6.1 contract, the v1.6.3 catalog still has 55
operations. The five related Link operations remain
`link.key_manifest`, `link.key_grants`, `link.key_grant`,
`link.review_policy_preview`, and `link.review_policy_grant`. The three key
operations gain explicit catalog/OpenAPI schema references; current accepted
Link-grant statuses may carry exact Owner proof and public-key evidence.
`link.review_policy_preview` and `link.review_policy_grant` retain their
existing request/response DTOs. The cumulative bundle also adds Group
`membership.set_directory_permission` and the Member snapshot's explicit
`directory_permission_enabled` field.

This imported public contract does not change the accepted Android runtime
contract pin, operation policy, or installed package. At this checkpoint the
Android baseline remains v1.6.1 / Core `144e079`, with 39 of 55 operations
implemented and 16 closed. The five related Link operations listed above
remain closed in the current Android policy. The new v1.6.3 Link proof DTO is
not evidence that an operation has been exposed: feature visibility still
requires a local implementation and permission in encrypted
`session.capabilities`. No v1.6.3 encrypted capabilities response was fetched,
and no new APK was built or installed. Existing v1.6.1 validation remains
separately attributed in
[`client-hub-v1.6.1-144e079-validation.md`](client-hub-v1.6.1-144e079-validation.md).

## Final source-bound Kotlin verification

After clarifying the verifier's authority documentation, the exact final
Kotlin source was compiled and its 16 tests rerun in the same offline pinned
development image. The clean imported vector and Android test asset were
independently compared byte-for-byte, SHA-256
`aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d`.
Exit was 0, duration 43.63 seconds, with 7 manifest and 9 policy tests,
zero failures/errors/skips. No APK was built.

The exact command, selected test hashes and final inputs are retained in
`/gpu1-share/data/cicada-client/link-consent-candidate-20261002/checks-final-bound-e8/checks-final/kotlin-host.receipt.json`,
SHA-256 `a55523394cec082a3415e20f598c6457fec9ec96fbf2679b70a38385fe8c9ee3`.
The log SHA-256 is
`73a08c25ff7dc0c51d157ca70a339ab561fbc4ab3111bffe7ee912a4768b9a88`.
Final source fingerprint is
`fdd6b5ed46272f841a5615c2adaba3f6d23ee36c9c085633cbc81c2476f60ca6`
over 129 files; tested Kotlin input fingerprint is
`306b12306049104005feca264a4530728aacad2ab709a4493170391374603604`
over 101 files, unchanged during the run. The [candidate record](client-link-consent-candidate-validation.md)
contains the final XML hashes and preserves every earlier pass/failure separately.
None of these host-JVM results establishes Android or live v1.6.3 acceptance.

### Remaining blockers

- **Reviewer permission:** The v1.6.3 wire contract says every METADATA reviewer
  must have current independent `link.review` permission. Its preview/status
  DTOs provide no proof or projection from which the Client can independently
  reconstruct that permission. The e8a029d
  `validateCommunicationLinkReviewersTx` checks Link Group membership,
  excludes the Link's source/target Endpoints, and checks current Endpoint,
  Principal, Group and Membership scope, but does not check `link.review` or a
  current leased SessionBinding for the reviewer. The separate message-review
  path does check that permission. Core has reported it is fixing policy
  preview and grant in a later delivery; this e8a029d release and its image
  evidence remain unchanged, and a future fix is not attributed as a v1.6.3
  pass. The contract requirement and policy-preview enforcement therefore
  remain blocked for independent Client validation.
- **Owner trust:** The new key-grant evidence is Hub-verified discovery data,
  not a trust root. The Client must compare the returned Owner identity to an
  independently trusted Owner key or pin. The wire contract provides no
  authoritative peer Owner trust source/global lookup; a Client must not
  auto-trust the Hub-returned key.
- **Bilateral review-policy proof:** `link.review_policy_status` remains
  metadata-only (`accepted_sides`); it does not return both policy proofs and
  independently trusted verification keys. The new OwnerLinkKeyGrant proof
  evidence is a different proof type and does not fill this gap.
- **End-to-end exchange:** The offline JVM results do not establish a live
  v1.6.3 Hub preview → independently verified Owner proof → grant round trip.
  The fresh encrypted `link.key_manifest` is the documented authoritative
  current Link/Endpoint scope snapshot; no separate `link.list`/topology read
  is required for that Link scope. The release manifest reports
  `inner_rpc_shapes=partial_prose_references`, `android_interop=NOT_RUN`, and
  `native_runtime=NOT_RUN`.
- **Runtime and device evidence:** Encrypted v1.6.3 `session.capabilities`,
  new APK/build, Android runtime, native Node/model execution, physical
  Android, and public HTTPS all remain `NOT_RUN`. Core's producer-recorded
  image/test gate is not an Android pass.
