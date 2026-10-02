# Independent Hub build-input inventory verification

## Purpose and trust boundary

The Client verifier checks the additive `source.input_inventory` in Core
source-only or image-build metadata. It uses Python's standard library and
read-only Git commands. It does not import or execute Core's inventory helper,
rebuild an image, alter a checkout, read a Hub database or start a service.

The caller supplies the complete expected Git revision. Catalog, source
fingerprint and helper SHA-256 pins may also be supplied independently.
Metadata equality alone does not establish a trusted image. Image identity,
contract provenance and encrypted runtime capabilities require separate gates.

The historical `fe565b4` metadata did not capture this inventory. The new tool
does not reconstruct rows for that image or revise its original provenance
limitations. See the [historical reconstruction supplement](client-hub-v1.6.1-fe565b4-provenance-supplement.md).

## Verification layers

| Layer | Checks | Meaning |
|---|---|---|
| Metadata parsing | Bounded regular-file input; duplicate keys and non-finite values rejected | A single unambiguous JSON record |
| Inventory structure | Exact scope, schemas, versions and domains; ordered unique safe raw paths; row type, complete mode, size, SHA-256 and Git metadata | A structurally valid captured inventory |
| Inventory fingerprint | Independent SHA-256 of the domain plus compact sorted ASCII JSON payload | The supplied rows and helper identity match the recorded inventory digest |
| v4 derivation | Raw path length/bytes, permission bits and content digest, skipping missing rows | The inventory independently reproduces the unchanged v4 fingerprint |
| Pinned Git | Complete clean scoped tree; independently read blobs, sizes, hashes, Git modes and index claims; helper and catalog identity | Clean content matches the expected immutable revision |
| Optional filesystem | Current scope, index, file types, full modes and bytes; no ancestor symlink traversal; drift rejected | Current filesystem inputs match the capture |

File mode and content provenance remain distinct. Git's `100644` may match
regular files with raw modes `0o100644` or `0o100664`; these produce different
v4 fingerprints. When filesystem verification is not requested, observed raw
filesystem mode equality is **NOT_RUN**. A digest recomputed from declared
modes is not an observation of their original capture time.

Leaf symlinks are represented by their target bytes under the inventory
contract. The verifier does not follow them to read target file contents.
Ancestor symlinks, traversal, inconsistent path encodings, unsupported file
types, clean missing paths and inconsistent identity claims are rejected.

## Final clean-image provenance check — 2026-10-02

Core `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c` subsequently supplied
complete build and source-only inventories. Both independently passed the
offline Docker verifier, exit 0, with `--verify-worktree`: 806 declared rows,
immutable tree/blob/index checks and 806 current raw filesystem modes matched.
Core status was clean before and after. Helper, catalog and unchanged v4 source
fingerprints matched the independent pins. Full Hub and interop image IDs and
their provenance labels passed separate checks.

The exact command, two metadata results, before/after tool hashes and image
checks are in
`/gpu1-share/data/cicada-client/client-final-144e079-20261002/provenance/independent-inventory-verification.receipt.json`,
SHA-256 `309d53dafd2795ac182540a7debb6593c92a56a5f473f63163cdebcad12224a8`.
The [current acceptance record](client-hub-v1.6.1-144e079-validation.md) attributes
the subsequent APK and Android gates separately. These current filesystem
observations do not certify earlier images or the historical capture time.

## Dirty source diagnostics

Dirty metadata is rejected by default. `--allow-dirty` permits an explicitly
labelled **DIRTY_DIAGNOSTIC_ONLY** report. Claimed Git objects and their content
may still be checked, but a capture-index reference is not automatically a
match to the pinned tree or the later current index. Modified or untracked
rows do not acquire clean Git provenance from the outer metadata revision.

The `648162…` source-only example is a dirty capture. Any diagnostic result
for that record is separate from a clean fixed-image acceptance result.
No diagnostic output authorizes Android operations or changes feature gates.

On 2026-10-01, the independent data-only check processed its 793 rows and
reproduced v4 `648162e9f52c2a14091f0537368097a2002dffb49b3f60a9e27fb43a07941985`
and inventory `3e0f6e1ebe8cb15681bcd03f73e3c347e5a9871cd1a1368da4ee414f9398904d`,
exit 0, **DIRTY_DIAGNOSTIC_ONLY**. The exact argv and log are at
`/gpu1-share/data/cicada-client/hub-input-inventory-20261001/diagnostics/dirty-data-only.receipt.json`.
This check establishes no Git, helper, actual filesystem, image or runtime
acceptance. Clean fixed-version results will be recorded with their own pins
and evidence after Core delivery.

## Historical offline tooling evidence — 2026-10-01

These results belong to uncommitted developer tooling following Client
`65d6a399122055e1bd38dfb70fa93686806bee36`. They do not replace the Android
target or authorize a new live run. The tooling and final candidate records
will be combined at the next complete milestone, without a tooling-only
commit. The application policy remains 39 implemented and 16 closed operations.

| Gate | Result | Exit | Evidence under `/gpu1-share/data/cicada-client/hub-input-inventory-20261001/` |
|---|---|---|---|
| Independent dirty 793-row data check | **DIRTY_DIAGNOSTIC_ONLY** | 0 | `diagnostics/dirty-data-only.receipt.json` |
| Synthetic validator/Git/filesystem/loader cases | **PASS_SYNTHETIC_ONLY**, 20 tests | 0 | `checks/unit-hub-input-inventory-final.receipt.json`, adjacent final log |
| Clean intermediate inventory and pinned Git | **PASS_PINNED_GIT_ONLY**, 793 rows and claims | 0 | `checks/intermediate-clean-git.receipt.json`, adjacent log |
| Current Core filesystem equality | **NOT_RUN** | — | Current Core worktree has subsequent changes |
| Final immutable image/contract proof | **NOT_RUN** | — | Final candidate not yet supplied |
| New APK build or Android/live acceptance | **NOT_RUN** | — | Outside this tooling checkpoint |

The clean intermediate source-only record belongs to Core
`06d0a582641ece2553cc824f52ec434cc1af59c8` and Git tree
`555fa3143244faace1bb0256ed359ffec707a7a3`. All 793 scoped paths, contents,
lengths, Git modes and index claims match that immutable tree. The pinned
helper blob is `8a0c4e8f12eb76c7a49cde620c4e2bc56db7a4ec`, SHA-256
`77b754ec8eb2782dfff063b26b5bc940b61e27ab8d971c542d66e5eb61c20b9e`.
Catalog SHA-256 remains
`6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b`.
The independently derived v4 fingerprint is
`648162e9f52c2a14091f0537368097a2002dffb49b3f60a9e27fb43a07941985`;
inventory SHA-256 is
`b38221cc9de0abbfaf2d22630755f0ea93e816c6d0a32bf351ed5a224e9692e8`.

The original metadata is
`/tmp/cicada-main-clean-checkpoint-20261001.source-info.json`. Its private
byte-identical copy is `inputs/intermediate-clean.source-info.json` under the
evidence root, SHA-256
`afaee421cdb944f35ebb0483214726e218e1cd6319789288c70bccd85bb1d2e2`.
Verification took 0.92 seconds and retained unchanged verifier files before
and after the command. Receipt SHA-256 is
`34c56f1b0f0b6ce8bd6fe76cea7b51289f5305cf4fa7d2b8b1a86cbea0cf38a0`.
It intentionally omits `--verify-worktree`; declared raw modes are validated
and used in v4, but actual filesystem equality remains **NOT_RUN**.

Exact commands are retained as structured argv in each receipt. The unit run
uses the same immutable development image, a read-only Client mount,
networking disabled and a private fixture directory. Synthetic Git commits
inherit the server global configuration through a read-only configuration
mount. Tests cover rehashed tampering, omitted and duplicate paths, modes,
blob/index/helper identity, replacement refs, dirty diagnostics, missing
helpers, symlinks, filesystem drift and ambiguous JSON metadata.

The final 20-test log SHA-256 is
`3ce56ac4eca6de0be2a66c61a72f9b97b9d6690e28686e373e23fd6b15192af5`.
Earlier iterative failed-run logs are **NOT_AVAILABLE**: they were overwritten
during test development, and their original commands and output are not fully
retained. The final passing log and a preceding passing log are preserved.
Neither synthetic run is evidence about Core inputs or an image.

## Usage

Run in an existing immutable development container with networking disabled
and both repositories mounted read-only. Do not execute the Core helper as
the proof under review.

```text
python3 scripts/verify-hub-input-inventory.py \
  --metadata <public-build-metadata.json> \
  --repository <read-only-Core-checkout> \
  --expected-revision <complete-fixed-Core-commit> \
  --expected-catalog-sha256 <independent-catalog-pin> \
  --expected-source-fingerprint <independent-v4-pin>
```

Add `--verify-worktree` only when that current checkout is the intended
captured source. A later checkout divergence is a mismatch, not grounds to
weaken verification. Retain the exact argv, exit code, verifier hashes,
metadata hash and output privately outside Git. Keep fixture tests, dirty
diagnostics, clean provenance, image identity and runtime acceptance separate.
