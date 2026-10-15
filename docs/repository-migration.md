# Repository and workspace migration — 2026-10-15

The development checkout is now `~/Cicada/cicada` on `dev`. Its parent
`~/Cicada` is a workspace, not a Git repository. Go Hub/Node/Windows App code
remains in `cicada-go`; Android is under `apps/android`. Authoritative Hub/App
contracts remain in root `docs` and `cicada-go`. The original source directories
are retained; no source code or Git history was edited. This is repository maintenance, not a product release,
deployment migration, protocol change or new acceptance result.

## Source and history mapping

| Source | Preserved destination |
| --- | --- |
| Core local `dev`, `dcf257727456095ee4dfe72b65925de017dc184b` | Exact initial destination `dev`; first parent of Android import |
| Android `dev/react-native`, `d266c5eb1e5b5d95df1d8388dc133dedea8b424f` | Second parent of nonsquashed subtree import `83cb76a735aeea3d26ab711fd3960df4211891f7`; tree at `apps/android` |
| Detached PQTLS worktree, `acec068e0066f8ea5fcf5492c9854c369f25fc83` | `refs/archive/migration-20261015/core/pqtls-worktree` |
| Core retained-worktree snapshots, `b92fc791cf7628be7a74fb8f44f79341032d33dd` and `b74e23693baa475adb628d90251a556078abc74b` | `refs/archive/migration-20261015/core/retained-worktrees-20261003` and `...-20261013` |
| Core reflog-only historical development and acceptance lineages | Six tip refs under `refs/archive/migration-20261015/core/reflog-*`, retaining all 221 otherwise unreachable commits |
| Android policy recovery `8af21cc29bdd063915fbb7b7f1262f6a0117ab57` | `refs/archive/migration-20261015/android/policy-terminal-20261003` |
| Android acceptance snapshots, Link recovery candidates and prior milestone history | Thirteen tip refs under `refs/archive/migration-20261015/android/reflog-*`; all inventoried source refs and reflog commits remain reachable |

The complete, machine-checkable source-ref, archive-ref and commit mapping is
[`repository-migration.json`](repository-migration.json). Original commit IDs,
authors, committers, trees and parent relationships are unchanged. Old commits
still use their original repository paths; only the import merge relocates the
Android tree. Historical validation stays attributed to its tested commit or
dirty-source fingerprint, software/wire/contract revision, image and environment.
Old failures, skips and NOT_RUN results are preserved.

Only `main` and `dev` are working branches. Archives use a separate ref namespace
and do not clutter the working-branch list. Each archive tip retains distinct
historical source, evidence or recovery history. The Android source-head archive
was unnecessary because import ancestry already retains that head. Unreferenced
tree/blob objects were not independently promoted into product history; all
unreachable Core commits were associated with meaningful reflog lineages. No
blanket copying of object caches or arbitrary dangling objects was used.

Destination `main` stays at `0a33932ba2abdc0462ee993ba5acc07078098a2b`.
The existing HTTPS `origin` and its refs were preserved; `origin/dev` stayed at
`308d7607cadc6cb83fe5aaa923adaf643a0aa32d` during migration. Source Core `dev`
was 32 commits ahead. No push, main merge, release or published-history rewrite
was performed. Local archive refs are local retention; a normal future push of
`dev` alone would not publish those archive refs.

## Transfer and verification

Core history was transferred with local Git fetch and explicit refspecs, then
`git switch dev` and `git branch --set-upstream-to=origin/dev dev`. Before any
integration edit, destination HEAD matched the clean source Core `dev` exactly.
Android was imported with:

```sh
git subtree add --prefix=apps/android /path/to/retained/CICADA_CLIENT \
  d266c5eb1e5b5d95df1d8388dc133dedea8b424f \
  -m 'Import Android App history into apps/android'
```

No squash or history filter was used. The imported Android tree was verified
equal to its original source tree before integration edits. Additional valuable
source refs and reflog lineage tips were fetched into the archive namespace.
Git Author and Committer inherited the existing global identity, checked with
`git var` before the import commit and verified afterward. No identity override
was introduced.

Run the read-only retention check from any checkout:

```sh
python3 scripts/check-monorepo.py --fsck
```

The initial Core history transfer passed full `git fsck`, had no object
alternates or object-directory environment dependency, and shared no object-file
inodes with the old repository. Both source working trees were clean and had no
stashes. Core had no submodules or LFS pointers. Existing nested historical
Core fixture source HEADs/refs were present in the transferred object database;
their dirty work and third-party caches are handled by the separate evidence
inventory, not silently discarded. The integrated validation results are
recorded in the [workspace guide](workspace-development.md).

Fetch does not preserve ancillary Git configuration or staged intent. A separate
private inventory therefore retains 26 source metadata files, including raw
reflogs, local configuration, ORIG_HEAD and commit-message files. Android's
three custom hooks are preserved as data; they were not installed over the new
checkout's configuration. Core/PQTLS hooks were defaults. No active local
exclude rules, rerere records, pending rebase/sequencer, merge, cherry-pick or
bisect state was found. All recorded ORIG_HEAD objects already existed in the
destination. No configuration or credential contents are published here.

An exhaustive nested-fixture object audit additionally found 50 distinct
non-commit objects outside the canonical object database: 31 trees, 17 blobs
and two tags. Their source/type mapping and two verified explicit-object packs
(292,425 bytes total) are retained privately under
`.local/migration/20261015/git-forensics`. `index-pack`, `verify-pack` and exact
object-set checks passed. Twenty-seven exact Git index files preserve staged
intent. These forensic artifacts do not add arbitrary orphan objects to product
refs. Historical captures are inactive evidence; their old embedded Git paths
are not a new, independently usable checkout or a fresh validation result.

## Workspace, evidence and operating boundaries

Use task worktrees at `~/Cicada/.worktrees/cicada/<task>` for concurrent writers,
with one coordinated owner of Git index/branch mutations per checkout. Do not
copy repositories or create permanent directories per AI. See the
[workspace development guide](workspace-development.md) for commands and roles.

Ignored historical artifacts live under workspace `.local/evidence/legacy`,
with protected inventories under `.local/migration/20261015`. Original receipts
are copied byte-for-byte; absolute paths embedded in historical receipts remain
their original source attribution. The ignored `.cicada-data` compatibility
alias keeps existing relative evidence links usable. New task outputs belong
under workspace `.local` with task-specific ownership. Root Docker contexts
exclude `.local`, `.worktrees` and Android because Go Hub images do not build the
Android App.

Active local OpenSSL/cache defaults use repository/workspace paths and existing
explicit overrides instead of the former absolute checkout paths. The native
observer's current-source checks derive the repository from their own file;
runtime preparation writes under workspace `.local/artifacts`. Its frozen
legacy helper imports, dependency pins, binding metadata and historical Docker
allowlists intentionally retain original paths. Rerunning those historical
Native gates after retiring the source requires newly reviewed bindings and
input path mappings; copied evidence does not make them a newly validated gate.
No paid Native calls were made. Repository
migration does not relocate resident container bind mounts, active emulator
storage, private keys, grants or deployment state. Those are separate local
state boundaries. The old directories must remain until their independent
inventory, consistency verification and live-path checks permit future cleanup;
this change deletes nothing and does not authorize cleanup or deployment
replacement. Private inventories and sensitive contents are not committed.

The terminal private preservation receipt is
`.local/migration/20261015/preservation-final-receipt.json`, SHA-256
`89ef31d889e3e3f518163065287e7a2bb934ed6043cd0b0615e1424131bd2983`.
The final legacy archive contains 171,206 regular files and 30,096,860,045
logical bytes (23,659,044,864 allocated bytes across distinct inodes), with
44,304 directories protected by mode 0700. All 315 original symlinks were
classified; the 307 retained links were audited. Source/destination inode
checks covered 187,435 retained files plus four recovered files. No dependency
on an old source path or private-permission failure remains in the archive.

The detailed receipt explicitly inventories excluded rebuildable caches and
compiler intermediates, removed redundant copied Git stores, pristine OpenSSL
extractions, stale sockets and recovered unreadable fixture files. All 38
recorded copy exceptions were resolved. Unique Git objects and staged indexes
were exported before redundant archived Git stores were removed; original
source repositories and raw reflogs were retained. Two exact owned disposable
fixtures were quiesced before their six state files were copied and freshly
hash-verified. The source was never used as a disposable Hub gate fixture.

New Android build housekeeping removed only CMake/Gradle intermediates after
the gate. Its 43 retained outputs/receipts (171,743,354 bytes) remain under
`.local/evidence/android/monorepo-migration-20261015`; inventory SHA-256
`061ffe50319abd0f934afabb11e5baf5f2cba48963e2e11fdebabb5c82491182`.
Scoped external-cache cleanup reclaimed 9,801,476,141 bytes and rechecked all
50 retained output hashes. These are local artifact operations, not deployment
replacement. Old AI/shell working directories remain an operating boundary:
close or move those sessions and prevent further old-source writes before any
future separately authorized deletion. No old source directory was deleted.

## Migration checks performed

The read-only migration checker plus full Git object check passed: 23 archive
refs, all 221 Core reflog-only commits, all 122 Android reflog commits and all
source refs retained. Android's original object scan found 18 unreachable
commits, all already represented in its reflog; there were no additional orphan
commit lineages to recover. No stash or uncommitted source work was discarded.

The authoritative contract check passed with `client-hub-v1.6.5`, 55 operations
and unchanged catalog digest; its 18 Python tests passed. All 59 native observer
default-fixture unit tests passed. The first relocation test run failed because
its mock still intercepted the former fixed root; the corrected test exercises
the file-derived root and a separate relocated source directory. This was a
fixture adjustment, not Native execution evidence. Changed shell/JavaScript/
Python syntax checks and `git diff --check` passed. Core `cicada-go`, `VERSION`
and `LICENSE` remain byte-identical to the preserved Core baseline.

The bounded task-worktree lifecycle also passed: a temporary
`task/migration-smoke` branch/worktree was created from the import HEAD, verified
to share only the new repository's common Git directory while using an
independent index, and checked for both Core and Android source. It remained
clean. Normal worktree removal and merged-branch deletion succeeded, leaving
only the canonical `dev` worktree and no temporary task branch.

The relocated native App foundation gate passed 55 tests with zero failures or
skips. The Windows cross-build produced 12,674,048 bytes, SHA-256
`7f5e3ddb6318a3c9f0cd3bb820b16b2b068f3b9f00f3546cf4312c3e52496a09`.
This is cross-compilation; native Windows/DPAPI/ACL execution remains NOT_RUN.
Its receipt is workspace
`.local/evidence/legacy/CICADA-data/native-app-foundation/run-20261015T102800Z-SdTvb3/validation.json`,
SHA-256 `cca8c414046aa50e3e39db5457692e6978ea0bb911776db7d23c0b10bc21a74f`.
`go mod verify` passed using the relocated canonical module cache.

The relocated disposable Hub interoperability gate passed its Smoke,
RecoveryFixture, HeadlessOperator and OwnerBootstrap suites, exit 0. Cleanup
was CONFIRMED for all five exact owned resources, each VERIFIED and EXACT_ABSENT.
The result is `.local/evidence/migration-gates/hub-interop/result.json`, SHA-256
`e0bf3a9f8637a2fc39150c059da1120a36b2ec6ee581fd5627db52a54d8a24d6`;
the cleanup receipt SHA-256 is
`28e90a541994ddfcb1406c7e6425ca18b4126c60c0af061a56949157055b90f6`.
Its image was
`sha256:1927fa1f75af934431e939a9aa85c2d7eb6c3c1795cf2d6d3fb7fc6f703506bf`,
built from dirty import base `83cb76a` with build-input fingerprint
`f2c62b99a275d887a0067189bfcfcc892564021a3d1a46ebbf4dab2a9c7dea11`.
Neither gate is attributed solely to that HEAD or to the later documentation
checkpoint. This Hub gate used standard transport, with PQTLS disabled;
Android execution, actual native Runtime and public HTTPS were NOT_RUN.
The separately built Android APK, 98 Node tests, 38 scoped JVM tests and other
offline results retain their precise scope in the
[Android migration record](../apps/android/docs/monorepo-migration-validation.md).

## Next development handoff

Continue 0.0.5 development on `dev`; the native Windows App remains N1 PARTIAL.
The next implementation boundary is N2: prove possession of the exact existing
Owner key, grant finite App-device authority, restore a trusted profile without
reusing installer authority, and reconcile retries and uncertain errors. Then
N3 connects the authorized live canvas and Node actions to the existing Hub
APIs and Guard. Preserve stable identities and user keys; changing keys is not
a substitute for missing proof/import support. These gates do not establish
new native Windows runtime acceptance, a finished Root activation or a release.

The supervising agent plans, reviews, validates and coordinates integration;
bounded implementation agents own code/document changes in assigned task
worktrees. Existing AI threads may retain an old cwd even after all repository
and artifact bytes are preserved. Those threads must cease writes before any
source retirement; new tasks start in their assigned new worktrees. Native
session identity and history are not recreated by moving a checkout.
`~/.codex` is outside the migration source glob and remains unchanged.
