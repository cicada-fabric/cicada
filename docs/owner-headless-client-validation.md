# Headless Client validation — 2026-10-13

Scope: the bounded Unix headless management Client in
[the operator guide](owner-headless-client.md). Software 0.0.4; contract
client-hub-v1.6.5, wire 1, catalog 55 and Hub schema 59 are unchanged. This is
INITIAL Node confirmation for an already initialized Hub and independently
registered Owner signer. Full account setup, first-signer bootstrap and unified
QR pairing remain NOT_IMPLEMENTED. UPGRADE confirmation is deliberately refused
because the current preview omits exact target binding/version.

**Bounded existing-Owner INITIAL headless scope: COMPLETE.** Final Docker A4
passed three top-level tests plus three recovery subtests with exit 0, no
FAIL/SKIP and confirmed owned cleanup. Normal-a6/race-r1 and targeted vet passed
their distinct SDK/CLI scopes. The current A4 local receipt is v2; this is not a
Client wire/contract or Hub database version change. Full product acceptance
remains PARTIAL, and the unimplemented/unrun domains below remain separate.

## Tested source and environment

The SDK/CLI checks used the dirty working tree based on dev commit
`5d187c3125909d5a648923fc0e1f97d7f8450f42`, not that commit alone. The scoped
input manifest is `.cicada-data/headless-client-20261013/scoped-inputs-a6.json`,
SHA-256 `bd375378f95c89d0b4ac7bf94aa9e357e1d1fd9b37c8c520191f407cc66a6729`.
It enumerates the SDK/CLI Go files and core version inputs; its hashes remained
unchanged through normal-a6 and race-r1. The metadata consistency test separately
checked VERSION, buildinfo and both existing plugin manifests. No image artifact
is claimed by these checks, and older 0.0.3 artifacts keep their original source.

Tests ran in disposable, network-disabled Go 1.27.1 containers from image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
UID/GID 1000, GOMAXPROCS 2, package parallelism 1, existing canonical writable
Go build cache and readonly module cache. All identities, Grants and Node
credentials were synthetic; Hub StateDir/Workspace and loopback TCP listeners
belonged to the tests. No resident/shared Hub or real keys were used.

## Closed deterministic results

| Check | Result | Scope |
|---|---|---|
| normal-a6 | PASS, exit 0; 16 top-level + 9 subtests, 3 packages, no FAIL/SKIP | New profile/session/Node/CLI cases plus version consistency |
| race-r1 | PASS, exit 0; 15 top-level + 9 subtests, 2 packages, no FAIL/SKIP/race warning | The same new SDK/CLI cases; version consistency is outside this race selector |
| Targeted vet-v1 | PASS, exit 0 | clientoperator, cmd/cicada and buildinfo |
| Client contract check | PASS | v1.6.5, 55 operations; catalog SHA-256 a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9 |
| Whitespace check | PASS | git diff --check |

The normal command was `go test -json -count=1 -p=1 -timeout=120s
./internal/clientoperator ./cmd/cicada ./internal/buildinfo -run
'^(TestProfile|TestOperator|TestClientOperator|TestVersionMatchesRepositoryMetadata)'`.
The race command added `-race`, used timeout180s, omitted buildinfo and selected
only `TestProfile|TestOperator|TestClientOperator`. Vet used the three packages
in the table. `python3 scripts/client-contract.py check` passed; go.sum is
unchanged and the existing go-isatty v0.0.24 entry merely became a direct dependency.

Private raw logs remain under `.cicada-data/headless-client-20261013/`:
normal-a6.jsonl SHA-256 `3c97f74c13f875da35861b9ba331333c48e5f790bcdf2e2ceb821831e882c36e`;
race-r1.jsonl SHA-256 `b9af26158481572224f03ac903a040621df7305cfb1a36a3db56b9807da55a4a`.
The logs are local evidence, not upload artifacts or sensitive payload exports.

The cases exercise exact expired accepted-enrollment retry after a lost response;
unchanged original ciphertext recovery across an actual same-store Control
restart; encrypted INITIAL Node preview/confirmation/list and lost-confirmation
retry; uncertain-confirmation fencing with readonly reconciliation; full public
key pin mismatch, redirects and wrong response sequence; wrong Grant/device
revocation; cancelled-before-send behavior; exclusive profile locking,
permission/symlink refusal and interrupted manifest export without rekey;
arbitrary/secret CLI argument refusal; real-TTY input with redirected approval
output refusal; and actual UPGRADE preview missing-target refusal before mutation
reservation. The upgrade fixture advances only a synthetic request's churn
timestamp to avoid a cooldown sleep, preserving all signed claims.
The locking case proves independent profile writers are rejected; it does not
establish support for concurrent methods on one Profile instance. The production
CLI calls methods sequentially, and library callers must do the same.

## Retained preparation failures and limits

Earlier preparation attempts are not converted to PASS. normal-a3 failed two
Node cases because the fixture used hex instead of the current base64url
credential digest. normal-a4 failed its new upgrade-negative fixture on the
production reissue cooldown. normal-a5 had a fixture compile failure from a
redeclared variable, so its SDK package did not run. Their raw files remain
beside the final logs. Initial tool-transcript-only attempts also exposed missing
explicit mode0700 fixture preparation; they have no archived full-source PASS.
Only the frozen normal-a6/race-r1 results above are the completed deterministic
SDK/CLI gate; the independently attributed Docker results follow.

An independent reviewer found no remaining blocker in the requested scoped
pin/transport/custody/Grant/recovery/approval checks after the material TTY,
manifest-recovery and upgrade-review corrections. The additional opt-in
independent-Hub Docker SDK test and existing disposable client suite are owned
by the root validator; their results remain separate from normal-a6/race-r1.

## Disposable Docker gate attempts

**A1 remains FAIL during build / NO_TEST**, exit 1. The Root tool transcript
retained the literal diagnostic `build-hub-image: source changed during the
Docker build; rerun from a stable checkout`. Original raw build stderr was not
retained, so its precise changed-input set is not reconstructed or described as
docs-only. No runtime HTTP test ran: result.json has build=null and all three
test exits -1. Its SHA-256 is
`09a3b76d0f68589ae6db1e81d111f3092e8677756b3435b222cf9920eed0cb63`.

Original A1 cleanup remains **UNKNOWN**, SHA-256
`febe4a092f164794b5040a5cb02b3ef2a0a0ca2ff494f80902915b054f0267a8`:
containers were not created, but the original cleanup retained both owned image
tags and scratch without final build metadata. The later independent
`docker-gate-a1/a1-owned-safety-closeout.json` is **CONFIRMED**, SHA-256
`ed513cc6e55f8b29bbe1440227b7f9ca5d19dc916dde293110d708bce691af29`.
It verified the exact A1 image tags/labels, no container references, removed
those tags without force/prune, removed only the verified empty scratch, and
confirmed all six protected residents unchanged. It touched no A2 resources.
That later cleanup does not rewrite A1's FAIL or original UNKNOWN receipt.

**A2 remains aggregate FAIL / exit 1**, although its test process exited 0.
Only `TestClientDockerHubSmoke` and `TestClientDockerHubRecoveryFixture` ran and
passed (two top-level tests, three recovery subtests). Required
`TestClientDockerHubHeadlessOperator` was **NOT_RUN**: the suite used the runner's
old two-test ENTRYPOINT instead of the new three-test selector. The original
result.json reports exit_code=0 inside headless_operator_test because it copied
the shared process exit; that field is not a named-test PASS. The sanitized
test.log lists only the two observed test passes. Original receipts remain
unchanged while dispatch/result reporting are corrected for a new attempt.

A2's producer was dirty dev `5d187c3125909d5a648923fc0e1f97d7f8450f42`, full
Hub build fingerprint
`4a5d31801e6465743abceee61f64e8d8e268a642ac64004201b84d2519d4629f`,
standard amd64 Hub
`sha256:eae01a57a47bd4bf288644539995c8dd5143910e9768603fd18832412bc3edcd`,
and test runner
`sha256:717e82d89514d69ccfd8be25808e403360f7e5bd4a55b1528fd12f7c4ec6a7fd`.
Contract v1.6.5, wire 1, catalog 55 and schema 59 remain unchanged. Its
build.json SHA-256 is
`a4a259b7f90236c2990581780cb0f3d999dab587ee55c180d697d2bd06a89da1`;
result.json SHA-256
`fdc1a079e1eddcc7663039b8c22a40444d145e9c748e7c0835a165c3750f87e6`;
test.log SHA-256
`b2263c4c5fb54e637d22b46bb7d137f06931e7fbccea491a96176812093e0177`.
A2 owned cleanup is **CONFIRMED**, cleanup.json SHA-256
`a4fb06ad51294b870d0bc50b13969d8bdaecbb7d2d7ae7ae1fa693d986114b61`.
All these local receipts are under `.cicada-data/headless-client-20261013/`.

Before A3, the three existing `CICADA_BUILD_VERSION` defaults in
docker/Dockerfile.hub and two in docker/Dockerfile.hub-pqtls were synchronized
from 0.0.3 to 0.0.4. Main docker/Dockerfile has no software-version override and
uses current buildinfo. No Runtime/base-image version or protocol changed.
These Docker inputs and the corrected gate dispatch produced newly attributed
build gates; they do not transfer new SDK coverage to A2 or change the frozen
SDK/CLI input hashes tested by normal-a6/race-r1.

**A3 passed its actual intermediate-v1 Docker SDK gate**, three top-level tests
and three recovery subtests, zero FAIL/SKIP, exit 0 and owned cleanup CONFIRMED.
Its dirty producer is the same dev base `5d187c`, with full Hub build fingerprint
`6afb9c20d6af7bc657267954cc066ef227cd397b77981b9d15658a80676ad6e4`.
Actual A3 Hub image is
`sha256:5d086059f817fa48f95996e0de5c72ce943a9db082aa00a09d9693c0d14d2434`,
runner `sha256:8257c452e098bc9f2940c58f5687d8f10eeb86639c26f78e5439522d1a1fdb55`.
Result SHA-256
`57f1ec0e9af122243eba9a4ba3ecafa20a9b25ea50be572732fd0731bcad26ec`;
cleanup SHA-256
`97d236047de35e0c1aa5080ddbdb1c20d37ad35375275cba3997036b33ef23c6`.
These intermediate results and receipts remain unchanged.

A subsequent wrapper audit found that removing common `test.exit_code` without
updating the existing fresh Link-completion consumer would break local receipt
compatibility. Affected local receipt families and strict consumers were
versioned to v2 and tested: Link formatter 33, completion runner 30 and Group-key
metadata 15, **78 Python tests PASS**. This is local metadata/consumer evidence,
not a fresh Link Docker run, Group-key Runtime acceptance or a public protocol
revision. It does not rewrite A3's actual SDK PASS.

**Final A4 current-v2 wrapper gate: PASS.** The independently running disposable
Hub passed `TestClientDockerHubSmoke`, `TestClientDockerHubRecoveryFixture` and
`TestClientDockerHubHeadlessOperator`, plus the three recovery subtests. Aggregate
exit 0, zero FAIL/SKIP; all three named-test statuses are PASS separately from
their runner exit. Owned cleanup is CONFIRMED. The SDK test uses a test-owned
loopback HTTP proxy to the separate Docker Hub, independently supplied synthetic
Owner/Hub public pins, and existing encrypted enrollment/Node RPC. It is actual
SDK/Hub TCP evidence, not actual interactive CLI approval or public HTTPS.

A4 producer is dirty dev `5d187c3125909d5a648923fc0e1f97d7f8450f42`, full Hub
build fingerprint
`6afb9c20d6af7bc657267954cc066ef227cd397b77981b9d15658a80676ad6e4`.
Its build inputs match A3, but the actual artifacts are distinct: Hub
`sha256:9893e6d24bb9d1416cba2b9d0f1c710a16521d012c8439a8545b92ac0ee80cf0`,
runner `sha256:7ab29a742e02519e5736a088ee4770ea9d9f29521ffedea9ad7a7584b3b918a2`.
Retained A4 receipts under `docker-gate-a4/`:

| Artifact | SHA-256 |
|---|---|
| result.json — cicada.client-hub-interop.v2 | 6b7e114d2f43595757f360328c00211e1d8396663f10d78ca224a4018e4e61f3 |
| cleanup.json | 8df67387bd78ce6fdca5e802637e02a1a7c89018474a213f743df72a3f6abfd2 |
| build.json | 6bcb557a552f1a9b1dd4bb8d0484de508718229ea8641d56a77948c321915972 |
| test.log | ad4b2f1dbb2a5391d2be920a1e41dec49443eb1443700f0596ae077aaed409d8 |

Software 0.0.4, Client contract v1.6.5, wire 1, catalog 55 and Hub schema 59 remain
distinct from the local receipt v2, dirty Git base, build fingerprint and image
digests. No Android source/APK changed. No historical ledger count or earlier
failure was relabeled by this closeout.

These checks are synthetic Go/HTTP evidence, not actual interactive CLI approval,
Android, native Runtime consumption, physical-device, macOS native custody or
public HTTPS acceptance. Those domains are NOT_RUN here. Windows custody fails
closed pending ACL implementation; cross compilation is not runtime acceptance.
No full Go suite, release, push, production migration, key rotation or resident
deployment replacement was performed by this scope. Overall product acceptance
remains PARTIAL.
