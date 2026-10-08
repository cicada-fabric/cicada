# Permission and Control-boundary protocol validation

## Current result — scoped protocol PASS, v0.1 PARTIAL

The tested source was clean `c56f7aed77ee02447ad7478b88a2b67619062bcb`, a docs-only successor to clean e286. The [selected PQ distribution-input fingerprint](../.cicada-data/native-observer-wiring-20261007/g5-protocol-c56-20261008a/inputs-before.NONAUTH.json) remained `365b182a8363c36423274b6c57569ac83a338688a23aeaa718aed4679a7d798d`: domain `cicada-pqtls-distribution-inputs-v1` covers source inventory plus runtime, including `.dockerignore`, scripts and tests, not only compiled units. The [optional PQ artifact](v01-clean-e286-artifact-validation.md) was built and shipped-tested on e286; neither it nor these tests is attributed to a future documentation commit.

| Run | Actual result | Scope |
|---|---|---|
| G5 permission subset | 8 top-level tests / 43 subtests / 3 packages; failure 0, skip 0 | Synthetic MCP, HTTP and Store permission fixtures |
| T9 Control-boundary subset | 2 top-level tests / 0 subtests / 2 packages; failure 0, skip 0 | Store/Fabric dependency fixture and fake-Codex protocol chain |

No aggregate full-gate PASS or completion percentage is claimed.

## Public evidence

Evidence root: `../.cicada-data/native-observer-wiring-20261007/`. These links address locally retained ignored NONAUTH evidence, not published assets.

- [G5 result](../.cicada-data/native-observer-wiring-20261007/g5-protocol-c56-20261008a/result.NONAUTH.json), SHA256 `21bc9d40bb1ea8ca598e1c6f7126cbd1c8fd206b95fb3a944b56ec9edd535af1`.
- [G5 closed events](../.cicada-data/native-observer-wiring-20261007/g5-protocol-c56-20261008a/events.NONAUTH.jsonl), SHA256 `3286cb18c457bc9bc785505d770135d4a398dbe9aa77f06d03e7a5bd81a29ad3`.
- [Main/Root G5 review](../.cicada-data/native-observer-wiring-20261007/g5-protocol-c56-20261008a/root-review.NONAUTH.json), SHA256 `89b19b9c0d2be85dab323ce61ccf8249e58c89197d617c64bd05f093f49b8e8a`.
- [T9 result](../.cicada-data/native-observer-wiring-20261007/t9-protocol-c56-20261008b/result.NONAUTH.json), SHA256 `2651f96848fb010a0faf29b05fcfc7615bf2b24cc0ddd85192501244af46cd7c`.
- [T9 closed events](../.cicada-data/native-observer-wiring-20261007/t9-protocol-c56-20261008b/events.NONAUTH.jsonl), SHA256 `1aa11c38b778e2107912c6a2dae32c8e51525141d67dbe7938de5ad2ca25d802`.

[Main/Root T9 review](../.cicada-data/native-observer-wiring-20261007/t9-protocol-c56-20261008b/root-review.NONAUTH.json), SHA256 `0682fbdfad35c7c1b37f1b4213f85776e6e035d52c8dfc9e7f5408af297e5ecc`, records the independent public evidence review; the coder child separately reported its read-only field/input/fixture review. [Main/Root inventory clarification](../.cicada-data/native-observer-wiring-20261007/t9-protocol-c56-20261008b/root-inventory-clarification.NONAUTH.json), SHA256 `3f2aee0f5464a44fc7368867d4ef4c467da6acbd828b46b48ffcb3492d546a5d`, independently reproduces T9’s 1,131-file root digest using its executed encoding. Raw logs remain private. Public events retain only Action, Time, Package, Test and Elapsed.

## Exact selector coverage

G5 ran once against `./cmd/cicada ./internal/server ./internal/store`:

```text
TestCicadaMCPToolsRequireExplicitJoin
TestFabricJoinAndHistoricalReadsWorkWithoutControlBusinessService
TestActiveNetworkHTTPWorksWithoutControlAndSeparatesCredentials
TestArtifactV2HTTPRejectsWrongGroupAndRevokedMembership
TestResolveApprovalForClientRequestRejectsStaleOrMismatchedAuthority
TestLegacyArtifactHTTPFailsClosedAfterScopedArtifactRefExists
TestLegacyFabricPeerRoutesAreRemoved
TestNodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl
```

This covers explicit Join and authenticated caller derivation (forged principal input is ignored, not proof of HTTP forgery rejection), wrong-bearer/current-membership denial, cross-Group and legacy Artifact rejection, stale/mismatched approval authority, removed routes and opaque same-Group traffic. The full hidden-object U/history/search/export/Thread-multigroup matrix is not covered. Artifact fixtures construct Control; the mixed subset is not uniformly nil-Control and does not measure a global business-call count.

T9 ran once against `./internal/fabric ./cmd/cicada`:

```text
TestControlBusinessDisabledPeerRPC
TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness
```

The first constructs Store + Fabric, excluding Control/planner/scheduler/reporting from that dependency graph. The second uses production MCP/local bridges, custom httptest routes and canned WhoAmI cards, Store/Fabric, synthetic sessions and recording fake Codex. It checks correlated sealed ASK/REPLY and queue protocol; it does not exercise the production Server handler, real model consumption, two physical hosts or measured global Control business-call isolation.

## Isolation, provenance and cleanup

Both exact Docker command vectors declared pinned Go 1.27.1 builder `69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, offline accepted OpenSSL 3.5.9/module cache, UID 1000, network none, read-only root/source/Git/stage/module cache, approved Go build cache writable, capability drop ALL, NNP, 4 CPUs, 3 GiB and 512 PIDs. The declared vectors included bounded executable tmpfs and a bounded noexec mask over source `.cicada-data`, with only fresh evidence and the approved owned Go cache rebound writable. G5 captured effective mounts; T9 live mount metadata was NOT_CAPTURED, so its completed-container mask and hardening are not independently observed. Test timeout was five minutes and outer bound seven minutes; no retries, Native or model calls occurred.

Each run's owned container/name was absent afterward; six protected resident closed-field metadata remained equal. T9 completed before live mount inspection: effective mount metadata is `NOT_CAPTURED_CONTAINER_ALREADY_TERMINAL`; only its declared exact command is recorded, with no repeat to reconstruct live metadata.

Selected before/after inventory files were byte-identical within and across runs, SHA256 `3a6cb2cd0af84dd10f2992486f03f2c58e366edc84d98f9130ff30b5096cae99`. Each full-root inventory had 1,131 files and matched within its own run: G5 `894e7439fc9e47d17214321c6d17fcaca4392a9cbd06e3cb2d50f01b90266909`; T9 `3b0a6959f2d10be708cf116c864b5f686c3361362d458c42dbde5ae181ea3091`.

Cross-run complete-root equivalence is NOT_ESTABLISHED: G5's exact inventory encoding was not retained. T9 hashes sorted deduplicated raw Git-relative path bytes as eight-byte big-endian path length, path bytes, decimal full `st_mode`, then binary file SHA256; no JSON or separators enter the digest. Historical receipts are not rewritten to reconcile these hashes.

## Remaining acceptance and next dependency

These fixtures do not close full G5/T9, Native context, G2/G3, all G4, V67 or current Client/Android/physical/public HTTPS gates. Control counts remain NOT_INSTRUMENTED; v0.1 remains PARTIAL. Sandbox execution remains BLOCKED, historical A6 cause UNKNOWN, G2 FAIL and G3 NOT_REACHED. Fresh Node local SEND/ASK and current V67 account-bound submission remain UNSUPPORTED by the inspected CLI/native APIs; this is not a claim about all future APIs. See [account-proof and submission-fence limits](native-local-direct-design.md). Ordinary MCP Hub Relay remains available under Guard.

Next is ONE separately scoped compatible supported-sandbox zero-model child preflight proving workspace allow / outside deny. Only afterward may separately authorized bounded original-thread G2/G3 retain the strict ALPHA/BETA/reply/final-context oracle, isolation, six actual / four manual / two automatic turns, 180+30+30-second deadlines, retries 0 and admitted TCP cap 16. That socket cap is not an observed HTTP POST count. Remaining domains close separately; no unsupported catalog allowlist, restricted-workspace legacy Landlock fallback or prompt-based safety substitute is promised.
