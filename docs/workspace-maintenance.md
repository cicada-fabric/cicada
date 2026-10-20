# Workspace maintenance and retained worktree source

This is the **2026-10-13 historical cleanup record**, using that day's paths,
worktree inventory and independent Android repository. Its restoration examples
and dependency descriptions are not the current workspace layout or new cleanup
authorization. Use [workspace development](workspace-development.md) and
[repository migration](repository-migration.md) for the canonical monorepo,
current task worktrees and Android subtree; retain the original evidence below.

The 2026-10-13 local cleanup retired sixteen auxiliary Git worktrees after
preserving their source and moving their ignored evidence. At that checkpoint the registered
worktrees were `/home/zyf/CICADA` on `dev` and the detached
`/home/zyf/CICADA_pqtls` toolchain worktree. Android then remained in the independent
`../CICADA_CLIENT` repository.

## Local Git retention

Ordinary local branches are `dev` and `main`. Two local maintenance refs retain
historical source without permanent auxiliary checkouts:

| Ref | Commit | Retained state |
|---|---|---|
| `refs/cicada/retained-worktrees/20261013` | `b74e23693baa475adb628d90251a556078abc74b` | Seventeen original bases and exact working-tree/index states; includes the retained PQ worktree |
| `refs/cicada/retained-worktrees/20261003` | `b92fc791cf7628be7a74fb8f44f79341032d33dd` | Existing archive checkpoint formerly named `refs/heads/archive/worktree-consolidation-20261003` |

The October 13 checkpoint has the original `dev` and unique PQ commit as
parents. It records 1,612 changed or untracked source entries and twenty staged
entries, including the different staged and working versions of the Native
`AM` file. Git reused existing objects; sixty-seven additional source blobs
contain 2,037,204 bytes. Original paths, bases, Git modes, raw file modes,
statuses, checksums, index trees and reconstruction details are in its
`manifest.json`. Ignored evidence, runtime data and credentials were excluded
from the checkpoint. Both commit identities inherited the server's global Git
configuration.

The October 3 ref migration created no commit: an atomic expected-old-OID
transaction moved the local branch ref to the maintenance namespace. Its
twenty-nine-commit ancestry and existing remote-tracking ref were preserved.
Neither maintenance operation published or rewrote history.

Inspect retained state directly through Git. Restore a checkout only when a
specific historical source state is needed:

```sh
git show refs/cicada/retained-worktrees/20261013:manifest.json
git show refs/cicada/retained-worktrees/20261013:restore_worktree.py > /tmp/cicada-restore-worktree.py
python3 /tmp/cicada-restore-worktree.py \
  --repo /home/zyf/CICADA \
  --worktree CICADA_native_e2e \
  --destination /tmp/cicada-native-e2e-review
```

The helper refuses an existing destination, creates a detached worktree at its
original base, restores its exact source/index state and checks the original
status and index fingerprints. Evidence remains external; the helper reports
its canonical location. Restoration is historical source recovery, not a new
validation run or an assertion that those changes belong in current `dev`.

## Evidence locations and active dependencies

Twenty-five ignored directories were moved by same-device rename to
`/home/zyf/CICADA/.cicada-data/worktree-evidence/<original-worktree-name>/`,
keeping their relative layout. All 56,702 regular files, totaling 6,491,407,097
bytes, retained their bytes, modes and inodes. Historical logs and source-bound
receipts were not edited. Markdown evidence-link targets now use the verified
relocation map where authorized; narrative source paths, revisions and hashes
retain their original attribution.

The following roots remain necessary:

- `/home/zyf/CICADA_pqtls` retains the OpenSSL 3.5.9 stage used by current build,
  Owner-signing and observer checks. Its older and accepted library builds have
  different `libcrypto` bytes and must not be treated as interchangeable.
- `/home/zyf/CICADA_real_codex_prep_20261002` retains pinned Native helper inputs
  and historical evidence. It is an external dependency directory, not a Git
  worktree.
- `/home/zyf/CICADA_task_handoff` is one temporary compatibility symlink to
  `.cicada-data/worktree-evidence/CICADA_task_handoff`. The target contains the
  original `.cicada-data` evidence; there is no registered worktree or copied
  product source at this alias. Existing Native absolute paths and pins resolve
  through it. The complete evidence inventory was verified byte-identically
  through the alias. Remove the alias only after its executable consumers have
  an independently reviewed path migration.

## Receipts and cleanup policy

Local machine-readable records are under
`/home/zyf/CICADA/.cicada-data/cleanup-20261013/`:

- `preservation-receipt.json` and `source-preservation-manifest.json` identify the
  Git checkpoint and exact reconstruction checks.
- `retirement-progress.json`, `evidence-moves.json` and
  `evidence-inventories/` record each retired tree, old-to-new location and file
  checksums/inodes. The inventories remain local with restricted permissions.
- `archive-ref-migration.json` records the unchanged October 3 checkpoint and
  ref mapping; `doc-link-repairs.json` records the mechanical link repairs.

Source was retired only after exact Git preservation; scoped restore operations
normalized the manifested tracked/index paths, and only manifested untracked
source paths were unlinked. Every worktree removal used normal
`git worktree remove`, with no force, reset or broad clean. Readable process
metadata and all Docker mount records showed no auxiliary overlap; kernel
permission restrictions prevented an exhaustive process-file-descriptor audit.

Disposable Go hash caches, Python bytecode caches and Docker build caches can be
removed after checking their exact contents and current consumers. Keep test
logs, validation receipts, retained binaries and images, accepted delivery
archives, databases, backups, credentials and unknown runtime data until their
purpose and dependencies are established. A cleanup receipt proves preservation
and resource management; it does not replace deterministic tests, Docker
interoperability or separate Native, Android, physical-device and public HTTPS
acceptance.
