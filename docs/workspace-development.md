# Workspace and concurrent development

`~/Cicada` is the workspace root. Its three repositories have independent Git
histories and publishing lifecycles:

| Checkout | Responsibility | Routine working branch |
| --- | --- | --- |
| `~/Cicada/cicada` | Hub, Node, Control, protocols, native App and imported Android under `apps/android` | `dev` |
| `~/Cicada/cicada-fabric.github.io` | Public documentation reading layer and generated static site | Existing site branch; publishing separately authorized |
| `~/Cicada/.github` | Organization profile and community metadata | Existing organization branch; publishing separately authorized |

The workspace root is not a fourth repository. `CICADA.md` remains the adopted
product specification. Implementation and validation claims belong in the
implementation records. Android's pre-import history and validation remain
attributed to their original source; moving code does not validate Android,
Windows, native Runtime, physical devices or public HTTPS.

## One writer per task worktree

The canonical product checkout integrates completed changes on `dev`. Each
concurrent writing task uses its own task branch and linked worktree:

```sh
cd ~/Cicada/cicada
git worktree add -b task/example ../.worktrees/cicada/example dev
```

Use `~/Cicada/.worktrees/site/<task>` and `~/Cicada/.worktrees/org/<task>` for
corresponding repositories. Resolve the repository first; a worktree belongs to
one Git common directory, not to the entire workspace. Assign a task owner,
base revision, allowed paths, tests, and integration owner before editing.
Parallelism requires bounded, nonconflicting ownership. Branch names and
worktrees are coordination tools, not security boundaries.

One owner serializes Git operations that modify a shared index, refs, worktree
registrations or integration branches. Do not run overlapping `add`, `commit`,
checkout, merge, rebase, worktree removal or maintenance against the same
checkout. A linked worktree has its own index but shares refs and object storage;
it does not eliminate shared Git coordination. Never remove an `index.lock`
merely because another process is slow. Check the owning process and task first.
Keep the server's global author and committer identities; check `git var` before
committing and inspect both identities afterward.

The integration owner reviews each checkpoint, runs relevant deterministic
checks and disposable Docker interop when implementation changes require it,
and integrates in order. Preserve historical failures and exact source/artifact
identity. Do not push, release, merge into `main`, replace resident deployments,
or rotate real keys without the applicable explicit authorization.

Before retiring a worktree, inspect tracked changes, untracked and ignored files,
its branch/ref reachability, processes and mounts. Preserve valuable work and
artifacts, verify the destination, and obtain the task owner's handoff. Never
use `git clean`, forced checkout, reset, `rm -rf`, or worktree pruning to resolve
an unknown state. An untracked file is not proof that a file is disposable.

## Local state, secrets and evidence

Workspace-local data lives outside every repository under `~/Cicada/.local`:

| Directory | Purpose |
| --- | --- |
| `state/<task>` | Exclusive disposable fixture or development state |
| `secrets/<scope>` | Existing protected credentials and keys; never committed |
| `evidence/<task>` | Receipts, logs and verification records with source identity |
| `artifacts/<task>` | Exact APKs, packages and other retained build outputs |
| `cache/<tool>` | Explicitly rebuildable tool caches, when useful |
| `migration/<date>` | Protected source inventory, path mapping and verification manifests |

The root and private subdirectories use mode `0700`; ordinary private files use
`0600`. Historical immutable artifacts can be owner-read-only, retaining execute
permission only where applicable. Never print credential contents, grants or
sensitive payloads into evidence. Do not initialize a deployment from synthetic
fixtures. Give each task its own state, ports, Docker names and fixture paths;
shared local state requires an explicit owner and exclusive maintenance window.
Never use a shared development Hub as a disposable test fixture or globally
prune Docker resources. Pin a running gate to its immutable image ID or digest;
do not reuse a mutable image tag as the identity of an active parallel test.

Caches may be read concurrently. Dependency installation (`npm ci`, Gradle or
toolchain installation), cache repair and dependency upgrades require an
exclusive owner or a separate cache keyed by task and lockfile hash through the
supported cache overrides. Never let concurrent installers write shared
`node_modules`. Retain one verified offline dependency closure when useful;
separate regenerable build intermediates from exact artifacts and evidence.

The 2026-10-15 migration preserves legacy data at these paths:

| Original location | Preserved location |
| --- | --- |
| `~/CICADA/.cicada-data` | `~/Cicada/.local/evidence/legacy/CICADA-data` |
| `~/CICADA_pqtls/.cicada-data` | `~/Cicada/.local/evidence/legacy/CICADA-pqtls-data` |
| `~/CICADA_real_codex_prep_20261002` | `~/Cicada/.local/evidence/legacy/CICADA-real-codex-prep` |

Historical receipts retain their original bytes, paths, source revisions and
validation attribution. The protected migration manifest records exclusions,
source metadata, SHA-256 hashes, destinations and any unresolved errors. A
compatibility `.cicada-data` symlink may expose archived paths to existing
readers; create new task data through `.local`, not inside that archive. Archived
files are evidence, not reusable deployment configuration. Do not edit archived
copies to make old receipts appear to reference a newly tested source.

Rebuildable caches and compiler intermediates can be excluded only with an
explicit inventory and a regeneration basis. Duplicated immutable artifacts may
share destination inodes after hash verification; no preserved file may share
an inode with a mutable source. A stable file hash does not establish a coherent
snapshot of a running SQLite database, WAL, keys and replay counters. Quiesce
owned writers and verify the complete state set before moving active fixtures.
External delivery paths under `/gpu1-share/data/cicada-client` remain external;
record exact APK/image/receipt identities before any scoped garbage cleanup.

## AI sessions and path changes

An AI session's native identity, working directory and Git worktree are different
objects. Moving the checkout does not move an already-running session's cwd or
retarget its tools. Existing sessions may continue referencing the old paths;
record their old/new cwd mapping, preserve original session history, and start
new tasks in their assigned new worktrees. Do not recreate a same-name session
and claim native-session continuity. `~/.codex` is outside the migration source
glob and is not a cleanup target.

Source directories can be retired only after the preservation manifest verifies
all valuable data, Git history and dirty work; symlinks are checked; active
processes and container mounts no longer depend on them; and each unresolved
permission or snapshot error has been resolved. A copy alone does not meet this
criterion. Deletion and publishing remain separately scoped operations.
