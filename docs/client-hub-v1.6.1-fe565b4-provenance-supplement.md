# Client-Control v1.6.1 build fingerprint reconstruction supplement

**Date:** 2026-10-01

**Scope:** independent read-only verification of the Core's retrospective public build-input manifest. This supplement follows Client milestone `d580975a83da0ef62dab0cdc6b139dc904d369e3`. It does not rewrite the [earlier BLOCKED record](client-hub-v1.6.1-fe565b4-validation.md) or its external delivery receipt.

## Result and provenance boundary

**PASS_RETROSPECTIVE_RECONSTRUCTION**, command exit **0**: an independent Client verifier checked all 773 scoped Git blobs at immutable Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, their Git modes, content SHA-256 values and lengths, the declared raw filesystem modes and corresponding read-only evidence. It recomputed the exact immutable v4 fingerprint:

`6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be`.

**Original build-time per-file mode capture: NOT_PROVIDED.** The Core explicitly classifies this material as retrospective reconstruction. Six modes come from same-byte files in its frozen C4 source snapshot; the other 767 modes were observed in the current filesystem during reconstruction. Matching the recorded fingerprint is corroborating evidence. It does not establish that these observations were captured at the original build, or certify the historical working tree. The surviving snapshot metadata records its base revision, count, path and time; it does not hash-bind the adjacent original per-file source inventory. Current file equality and declared mode observations are independently checked, but historical creation time and mode continuity are not cryptographically established. The original build-time provenance gate therefore remains **BLOCKED**. The original algorithm includes non-ignored untracked inputs; this manifest enumerates the pinned tracked tree and relies on the immutable build metadata's declaration that the build was clean.

The archive, catalog, Hub image and delivery report are unchanged. No Android APK is rebuilt or relabeled. Prior APK test results remain attached to the exact source and artifacts that produced them. No Hub, Node, native Session or model run is performed by this supplement. Current live Hub, native-runtime, physical Android and public HTTPS gates remain **NOT_RUN**; real Monitor acceptance remains **BLOCKED**.

## Immutable inputs

| Item | Value |
|---|---|
| Core revision | `fe565b41bb1aa86d400a0ec98c528c856d0b9579` |
| Pinned Git tree | `a1e2ae4bc90d9897e4dac252a9daf3d915777fa4` |
| Protocol | `client-hub-v1.6.1`, wire 1, 55 operations |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Archive SHA-256 | `b5757b055bc871ef5f19fcc5ffe425813c6dea2ccc8cc64b4e74e1f1dcd8db55` |
| Hub image ID | `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589` |
| Retrospective manifest SHA-256 | `1177e6045120082c3871f81afca9ec938364e132598c016645abe0a66bfd02aa` |
| Core reproducer SHA-256, inspected only | `1db351e37eded5e4453ba092527e363b4c2b23b287f3e51e0e83f5cb5bb9fd1a` |
| Client verifier SHA-256 | `8b0ad84dc2e378ce8371b757d50fb5ddb805b47428a78e6e16466f57969691cc` |
| Independent verification receipt SHA-256 | `bb87bbb71e6c841707c7c15d73f863424991bbfcca22b19d8b60cf3ed989da98` |

The public manifest and reproducer are `/home/zyf/CICADA/.cicada-data/transport-recovery-delivery-20261001/build-input-manifest-v4.json` and adjacent `reconstruct-build-input-v4.py`. The Client did not execute that reproducer because it writes to the Core repository. The independent verifier writes no files, reads Git objects and explicit public mode evidence, and runs with both repositories mounted read-only and networking disabled.

## Independent algorithm and checks

The exact domain bytes are hex `6369636164612d6875622d6275696c642d696e707574732d763400`: the UTF-8 prefix `cicada-hub-build-inputs-v4` followed by exactly one NUL byte. For each scoped path in byte order, hash its uint64 big-endian path length, raw path bytes, uint32 big-endian filesystem permission mode, and SHA-256 of the pinned Git blob. Printable backslash/digit-zero bytes are not substituted for NUL.

| Check | Result |
|---|---|
| Manifest and inspected reproducer SHA-256 match the separately delivered pins | **PASS** |
| Pinned revision/tree, complete sorted scoped set, 773 blob IDs and Git modes | **PASS** |
| Every pinned blob's content SHA-256 and byte length | **PASS** |
| Six snapshot files equal their corresponding pinned blobs; snapshot metadata hashes and raw modes match | **PASS** |
| 767 explicitly recorded current filesystem modes match their read-only observations | **PASS** |
| Raw mode distribution: `0644=15`, `0664=756`, `0755=1`, `0775=1` | **PASS** |
| Independent exact v4 domain and fingerprint recomputation | **PASS**, exit 0, 2.91 s |
| Original build-time per-file modes directly captured | **BLOCKED** (`NOT_PROVIDED`) |
| New Hub / native / model / Android acceptance | **NOT_RUN** |

The Client verifier is [scripts/verify-hub-build-inputs-v4.py](../scripts/verify-hub-build-inputs-v4.py). The actual command was:

```bash
docker run --rm --pull=never --network=none --read-only --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  -v /home/zyf/CICADA:/home/zyf/CICADA:ro -w /workspace \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 scripts/verify-hub-build-inputs-v4.py --core /home/zyf/CICADA \
  --manifest /home/zyf/CICADA/.cicada-data/transport-recovery-delivery-20261001/build-input-manifest-v4.json
```

The command exited **0**. The receipt, exact argv, verifier digest and result are at `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/provenance/supplement/independent-v4-verification.redacted.json`. This receipt is separate from the original `client-delivery.redacted.json`, whose BLOCKED state remains intact. The supplementary Client commit is recorded in an adjacent `client-supplement-delivery.redacted.json` after commit; no push or merge is performed.

## Core maintainer handoff

> Client independently reproduced the immutable v1.6.1 fingerprint from the pinned 773 Git blobs and the declared retrospective modes. Preserve the distinction between retrospective corroboration and original build-time capture. Do not relabel the earlier BLOCKED report or Android/native results. For future deliveries, capture the exact sorted input inventory, per-file raw modes and content hashes at build time, or define a versioned reproducible fingerprint using canonical permission rules. Keep any new source, archive, catalog and full image IDs separately fixed. A real Hub/native/Monitor acceptance run requires separate authorization and current artifacts; this supplement starts none.
