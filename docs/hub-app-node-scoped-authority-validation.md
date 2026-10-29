# Node-scoped App/NPT shared codec validation

2026-10-29 producer checkpoint, **CODEC_ONLY_UNAVAILABLE**. Contracts:
[finite authority](hub-app-node-scoped-authority-contract.md) and
[independent NPT](node-pair-trust-scoped-contract.md).

Tested source is base `d4566fcd969424dc47ab811bfdcfd8c65afc59e2` plus the
explicit dirty-file inventory in
`/home/zyf/Cicada/.local/evidence/app-node-scoped-codec-20261029-01/tested-source-manifest.json`,
SHA-256 `8e775f020da67e14ff78dd0f2a75f4b8996f2f7bc849d0d070411dbcdaab5c85`.
That inventory includes two unchanged Store dependency files as extra source
inputs; it is not the checkpoint's Git file list. The diagnostic-only commit
`98ed4e21d06476b41b75b4d3fee5f88696a4c6a2` was created after these source files
were frozen. Its unrelated `cmd/cicada` change is outside these tested packages.
This is not a clean-HEAD-only build attribution.

## Deterministic and disposable gates

Normal full `internal/e2ee` and `internal/hubaccountwire`: **174 top-level PASS**,
zero FAIL, **one SKIP**, package elapsed 0.673s and 5.111s. The optional external
`TestExternalOwnerOpenSSLRealSignatureInterop` skipped; it is not a pass.
`crypto-wire-normal.jsonl` SHA-256
`a41be5318b62f7709215169a87586749bc018035a5fbd6f1df13aa9cfa6a82f0`.

Normal isolated Server TCP: **2 PASS**, zero FAIL/SKIP, 3.086s. This runs the
existing N3 activation/Owner proof/confirmation/heartbeat/READ_EXISTING chain and
the new false-only discovery/method/closed-POST check.
`tcp-normal.jsonl` SHA-256
`6dcd42a576e41020aa34070ed6a4f83685161ae40e41a2f62bef82e9a48d2067`.

Disposable Docker: **11 top-level PASS**, zero FAIL/SKIP: nine scoped wire tests
(0.486s) and the same two Server TCP checks (3.152s). Image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network disabled, UID/GID 1000, read-only source/root/module cache, disposable
tmpfs and existing Go build cache. Test binary hashes, exact commands and raw
events are retained under `docker/`; the owned container is absent afterward.

The post-completion host receipt-count parser raised TypeError, so its wrapper
exited 1. This historical harness failure is retained. Both test package
terminals are PASS; the exact container's Docker `die` event independently
records **exitCode=0**, retained in `docker/completion-events.jsonl`, SHA-256
`b1e9d42604e0c052d4ff4682901b26e69b879d8e7163e4401f7989f25f7c6b48`.
`docker/receipt.json` records both results and their distinct attribution; no
test rerun or source change was used to replace the original logs.

The joint Python metadata check passes both unchanged `app-node-authority-v1`
and the new scoped contract, asserting wire/catalog, distinct routes/purposes,
Scope2, exact operation/DTO inventory, unchanged finite bounds and availability
false. `git diff --check` passes.

## Tested boundary and remaining work

New tests exercise real synthetic PQ envelopes and Owner signatures, strict
v1/new isolation (including an empty unknown field), exact candidate/binding
Node match, READ_EXISTING without a confirmation, XOR status resolution,
explicit head-zero Owner identity projection, `n3s.` original selection,
cancel/reconcile original binding, new secret-code matching, original Node
pairing proof, all twelve NPT request operations, independent local-secret
capsule/ACK verification, and an authenticated recovered receipt with identical
original bytes. They use only isolated temp state and visibly synthetic keys.

Both new capabilities remain false and scoped POST routes remain closed. No
Store migration or live scoped grant/confirmation carrier is implemented by
this checkpoint. Per-Node transactional CAS, global pending/RESERVED and
cross-namespace provenance behavior, crash/restart persistence, account/Owner
revocation across scopes, restore inventory, actual second Node through the
App into an existing Network and Group all remain **NOT_RUN** pending carrier
and consumer implementation. Race, Android, actual native Runtime, physical
Windows and public HTTPS are also **NOT_RUN** here. Existing v1 tests and the
new shared codec tests do not establish those acceptance scopes.
