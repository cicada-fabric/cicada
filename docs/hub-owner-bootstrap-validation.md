# Hub first Owner signer bootstrap validation

Status: **bounded checkpoint SCOPED PASS; full product acceptance remains PARTIAL**.
Docker A2 passed the fresh-Root flow, manager Client enrollment and existing
Node INITIAL path over TCP. Normal and selected race coverage completed in
segmented runs after two Store test-fixture-only corrections; vet, build and
both Python suites passed. The original A7 normal and R3 race aggregate attempts
remain recorded as failures and are not relabeled as one-shot passes. Skips are
not passes. Do not treat a synthetic vector, a build, or an older Client smoke
Hub as protocol acceptance.

| Evidence | Status | Scope |
|---|---|---|
| Source and test selector review | PASS | Required Docker test ran once; selector and formatter recorded the named `owner_bootstrap_test` result |
| Deterministic Go suite | SEGMENTED PASS; aggregate A7 RETAINED FAIL | A7 exited 1 after two old Store migration-fixture assertions and a 240-second Store timeout. After test-only fixture corrections, segmented normal runs covered all eight related packages with 1,235 top-level PASS events and 1,165 unique `(package,test)` subtests; 24 skips (21 opt-in Native/Docker and 3 privileged bind-alias) are not passes. The post-fix Store batches all exited 0. |
| Selected race suite | SEGMENTED PASS; aggregate R3 RETAINED TIMEOUT | R3 exited 1 on the Store package timeout after seven other packages and 11 Store top-level tests passed. The two remaining selected Store tests passed in R4. Combined selected coverage was 58 top-level tests and 27 subtests PASS, zero skips, with no data race reported. R3 is not relabeled as a one-shot race PASS. |
| Vet and build | PASS | Corrected fixture-input `go vet -p=1` over the eight selected related packages and `go build -p=1 ./...` both exited 0. The build check is not a release artifact. |
| Python helper checks | PASS | Python A3 passed 98 tests; installer-update suite passed 21 tests, including pristine-state refusal and existing update/backup behavior. |
| Disposable Docker real-TCP Hub + owner-signer/Client SDK | PASS (A2) | `TestClientDockerHubOwnerBootstrap` used a separately started built Hub process and owned state; the configured OwnerID received manager capabilities, while a cryptoID-only external identity did not. The fresh Root then enrolled the manager Client and completed the existing synthetic Node INITIAL preview/confirm/list flow on the same Hub; OwnerID and confirming Client device bindings were checked. |
| Lost accepted response and exact retry | PASS | The first accepted response was dropped; recovery repeated the exact proof and authenticated the cached receipt |
| Hub-side Owner-key custody observation | PASS (bounded) | Test fixture searched the owned Hub StateDir for the exact serialized synthetic Owner identity and source review verified public-only persistence; this is a bounded pattern check, not exhaustive secret-flow analysis |
| Restart / revoked-Root no-reset checks | PASS | Root history persisted across restart; revoked Root proof and re-bootstrap were rejected |
| Existing Node INITIAL path after this new Root | PASS (bounded protocol/SDK scope) | The A2 fresh-Root case enrolled the manager Client, then used the synthetic Node protocol fixture to execute INITIAL preview, review, confirmation, and listing on that same independent Hub. It did not launch a Node Agent or test native Runtime, Android, physical hardware, or unattended Node operation. |
| Android Client | NOT_IMPLEMENTED / NOT_RUN | Android does not implement this bootstrap protocol |
| Native Runtime | NOT_RUN | This protocol test does not exercise a model/provider runtime |
| Physical device | NOT_RUN | No physical device run recorded |
| Public HTTPS | NOT_RUN | Loopback Docker protocol evidence does not validate public TLS or deployment exposure |
| Human interactive CLI review | NOT_RUN | No real operator completed the TTY approval prompts end-to-end; the Docker case seeds a trusted local synthetic fixture and tests the SDK/profile protocol. |
| Windows Owner-signer custody | NOT_IMPLEMENTED | The new private Owner profile is Unix-only; no Windows private-key custody flow exists. |
| Lost-Root recovery | NOT_IMPLEMENTED | Revocation/no-reset is tested; recovery after loss of the Root private key is not provided. |
| Owned fixture cleanup | PASS | A2 cleanup receipt confirms removal of 3 containers, 2 images, and private scratch state |

## Acceptance record

The corrected Hub/server source tested by Docker A2 used dirty Git HEAD
`9631d738c54a9760d7092946e799e2fdd5f4fa56`; its Hub build input fingerprint was
`680ca33e2260747114d99c012b620a2c0f193793c7efdcdf269946f9bc731e29` over 1,013
inputs. After A2, only two unrelated Store test fixtures were corrected; the
final segmented normal/race/vet/build input fingerprint is
`429abd7805dd39f058ec265cb2571e75f7afe3a526e22428badab0cf9939aa78` on the same
dirty HEAD. Its [final input inventory](../.cicada-data/hub-owner-bootstrap-20261013/final-fixture-corrected-inputs.json)
has SHA-256 `a3a3c661c3ec00b25775c661ee9a94a476924c5808c031b162ffb9ecb42785a4`.
The [fixture mapping](../.cicada-data/hub-owner-bootstrap-20261013/fixture-only-source-mapping.json)
records that the only post-A2 Hub-input changes were the Store test files
`client_intents_v2_test.go` and `external_thread_invites_v2_test.go`. These are
dirty-source identities, not artifacts attributable solely to HEAD. The
retained A2 images and Docker result remain attributed to their original FP
`680ca...`; that A2 artifact was not rebuilt for the later test-only fixture
edits. The standard amd64 Hub image was
`sha256:e2ae49b33fcb827cde9bd79312f36c6c5f17077500fc8da79e2f40508f9c0709`; the
interop test image was
`sha256:06138c37988bdc067a5eabd9933092a7619db14b04b34499a25d14b2f03f2572`.
The Client contract/catalog check passed for v1.6.5/catalog 55 (catalog digest
`a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9`). The
corrected-source full normal aggregate A7 exited 1 after
`TestClientIntentV19MigrationPreservesLegacyIntentRows` and
`TestExternalThreadInviteMigrationRollsBackAndPreservesLegacyRows` failed; the
Store package also hit a 240-second timeout after 167 top-level tests passed.
The client-intent fixture broadly rewound the migration ledger while retaining
objects created by newer migrations; the external-invite fixture hard-coded an
expected ledger ending at migration 59 even though the current ledger had
advanced. A7 reported
907 top-level and 888 subtest passes, plus
21 skips for opt-in Native/Docker lanes. The [A7 event log](../.cicada-data/hub-owner-bootstrap-20261013/full-normal-a7.jsonl)
has SHA-256 `dc17ac457185bddd29da7a4183dd3bb5f7727dd2a0f52ff30ddd64ef77ec7add`;
stderr is empty. The run remains a failure. After correcting only those two
test fixtures, six Store normal batches all exited 0; with the A7 and seven
other completed package results, the segmented eight-package record has 1,235
top-level PASS events and 1,165 unique `(package,test)` subtest passes. It
records 21 A7 opt-in Native/Docker skips plus 3 Store
bind-alias skips; skips are not passes. Batch exits are in
[`store-retry-exits.json`](../.cicada-data/hub-owner-bootstrap-20261013/store-retry-exits.json)
(SHA-256 `b3164260edad81e5c40ca27103567b553a3d8375f2e870641382ce7658a97eac`).
The consolidated [checkpoint closeout](../.cicada-data/hub-owner-bootstrap-20261013/checkpoint-closeout.json)
records the segmented counts and status (SHA-256
`2427027a9d6a5aaf0abd0f58ccbdbc3949af8cea4f6cfcd957ca753c0fdb4fe0`).
The earlier A6
normal run passed 55 top-level tests plus 19 subtests with no failures/skips;
its `go vet` run exited 0, but those checks predate the final corrected source.
Python helper suite A3 passed 98 tests. Earlier Python A1/A2 attempts ended in
import errors caused by an incorrect module path, not source assertions. Shell
syntax and `git diff --check` passed. The 21-test installer suite also passed
after the fresh-state fail-closed adjustment; its log is
[`installer-tests-a1.log`](../.cicada-data/hub-owner-bootstrap-20261013/installer-tests-a1.log)
(SHA-256 `4f5b4bf511dd2e56919f457d2af7aa1b83878cae3488ae69ec839016ef2e799c`).

Docker A2 exited 0 with four top-level tests and three recovery subtests
passing, including the required named Owner-bootstrap test. The one-shot setup
container exercised the `hub setup` CLI. The independent first-Root case used
trusted local Store/Control APIs to initialize its separate synthetic fixture,
then exercised the Owner-signer profile and SDK over TCP; it did not exercise
the `owner-bootstrap-issue` CLI's interactive TTY review. After Root bootstrap,
the same Hub accepted manager Client enrollment and the synthetic Node INITIAL
preview/confirm/list path. The [A2 result](../.cicada-data/hub-owner-bootstrap-20261013/docker-a2/result.json)
is PASS (SHA-256 `27e0c58641a6bbb9c5bb3d2da89666f885cfe3bf586cbd14c261065cf6ba2896`);
the [test log](../.cicada-data/hub-owner-bootstrap-20261013/docker-a2/test.log)
hash is `11937b6f69af2b18b5500055413f5b6b82703708d1471283dc6c319b48cb04c0`.
The [cleanup receipt](../.cicada-data/hub-owner-bootstrap-20261013/docker-a2/cleanup.json)
is `CONFIRMED` for all five owned resources (SHA-256
`af8f5e2c9cf2359ed7fb7606385128db3a8f87eb107980b1478d11f73808227b`); the
[build receipt](../.cicada-data/hub-owner-bootstrap-20261013/docker-a2/build.json)
SHA-256 is `c220ad88c4f81096d442c5dcec0324e6b28b23d77091da11dc0a5315453e65b9`.
The receipt directory is
[`docker-a2`](../.cicada-data/hub-owner-bootstrap-20261013/docker-a2/).

Earlier Docker A1 remains a separate successful attempt on the dirty source
fingerprint `1d698fdbeb4c485a5ce129cf759afbf6e15e740d65b335bdd71ecac58d61c8cc`,
with Hub image `sha256:8d5f3a3e7b648df72514bbfd689b26760f41a96bc848450776aaa3492244af8c`
and test image
`sha256:d2ae7d48beb7dd87b5aac5a45bcfcec194d144af2f2e6c606802df7d011534a6`.
It passed its four selected top-level tests and three recovery subtests, but it
predates the fresh-Root manager-Client→Node INITIAL chain added to A2. Its
[result](../.cicada-data/hub-owner-bootstrap-20261013/docker-a1/result.json)
SHA-256 is `e7cf9ae22cc678e59527e095dcba9b9ad8c322f2dbb8ac44d4cf232f71031bf0`;
its [cleanup receipt](../.cicada-data/hub-owner-bootstrap-20261013/docker-a1/cleanup.json)
SHA-256 is `6576e0d115051517f2f6c5795d4447725912a59bcd173a7d9f578194297bfb00`.
Do not attribute A1 to the corrected A2 input fingerprint.

The [A7 normal test event log](../.cicada-data/hub-owner-bootstrap-20261013/full-normal-a7.jsonl)
and [stderr](../.cicada-data/hub-owner-bootstrap-20261013/full-normal-a7.stderr)
retain the corrected-source normal run and its Store fixture failures. The
[A6 normal test event log](../.cicada-data/hub-owner-bootstrap-20261013/final-normal-a6.jsonl)
and [Python A3 log](../.cicada-data/hub-owner-bootstrap-20261013/python-a3.log)
retain their earlier passing records. Race attempt R1 exited 1 after 6 packages passed
(41 top-level tests and 19 subtests); `cmd/cicada` and `internal/buildinfo`
reported missing Go build-cache artifacts and failed at BUILD. No data race was
reported, but those packages did not run. The [R1 event log](../.cicada-data/hub-owner-bootstrap-20261013/final-race-r1.jsonl)
and [stderr](../.cicada-data/hub-owner-bootstrap-20261013/final-race-r1.stderr)
retain the attempt. R2 passed the two missing packages in an isolated cache,
but the R1/R2 combination predates final source corrections. On the corrected
fixture input, R3 exited 1 when the Store race package reached its 240-second
timeout, after seven other packages and 11 Store top-level tests passed; its
remaining Store work began with only six seconds of package budget left. No data
race was reported. R4 ran the two remaining Store tests separately: both top-
level tests and ten subtests passed. Combined selected race coverage is 58
top-level tests and 27 subtests PASS, zero skips; R3 remains a timeout failure,
not a single aggregate race pass. See the [R3 events](../.cicada-data/hub-owner-bootstrap-20261013/final-race-r3.jsonl)
(SHA-256 `3285860a63f360ff3bb51bca863ef45b8f0f93edeae8fd38a716fff0e21fc9e1`)
and [R4 events](../.cicada-data/hub-owner-bootstrap-20261013/store-race-r4-b1.jsonl)
(SHA-256 `76482ee5f72329b47a8d6668501c04a332d55e5e1b36340eb97001b0e0f11d4e`).
Final `go vet -p=1` over the eight selected related packages and `go build -p=1 ./...`
both exited 0; their zero-byte logs and exit records are retained under the same
evidence directory. The build is not a release artifact.
Earlier failed attempts remain attributed to their own logs; in particular,
normal attempt A5 passed 54 top-level tests and 19 subtests before its build
metadata check failed because `.agents/plugins/cicada/.codex-plugin/plugin.json`
still reported 0.0.4. The [A5 test events](../.cicada-data/hub-owner-bootstrap-20261013/final-normal-a5.jsonl)
and [stderr](../.cicada-data/hub-owner-bootstrap-20261013/final-normal-a5.stderr)
retain that attempt. The metadata was corrected before A6; A5 is retained as a
failure and is not relabeled PASS. Do not call this Docker HTTP protocol
acceptance Android, native Runtime, physical-device, human interactive CLI, or
public HTTPS acceptance.

Resource-bound note: the accept handler limits packet bodies to 256 KiB and
permits two concurrent proof-verification slots. The current listener's global
read timeout bounds slow bodies at two minutes; a shorter route-specific body
deadline is a small follow-up hardening item and does not change the protocol
surface.

## Required run

The mandatory `client` Docker interop gate must select
`TestClientDockerHubOwnerBootstrap`. Its selector must fail if the test is
omitted, skipped, or run more than once, and its result must expose a distinct
`owner_bootstrap_test` status (`NOT_RUN`, `PASS`, `FAIL`, or `SKIP`). This named
field is additive to the existing local receipt schema; existing strict
consumers must continue to validate their required fields.

The test fixture must create a disposable state directory itself, with a
canonical regular mode-0600 marker containing exactly `disposable\n`; it must
not reuse the main interop Hub's database, whose smoke setup already registers
a compatibility Root. The first-root case must launch the built Hub binary as
an independently running process, use a local signer profile and the actual
SDK/API over TCP, and clean up the owned process and directory even on
failure.
