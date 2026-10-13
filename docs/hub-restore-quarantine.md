# Hub restore startup quarantine

`migration restore` preserves the verified archived files, identities and
counters. Archive integrity is not proof that archived counters or authorization
are current. The restored Hub is held; there is no release, activation, counter
reset or key rotation command in this change.

For canonical absolute target `TARGET`, the restore operator owns two private
records: `TARGET/.hub-restore-pending.json` and
`parent(TARGET)/.hub-restore-pending/SHA256(TARGET).json`. The registry directory
is mode 0700 and belongs to the effective restore/startup UID; records are 0600.
This namespace is parent-local, not a global configuration or `$HOME` registry.
Existing registry permissions/ownership are never broadened. Existing parent
aliases resolve to the same target coordinates; a symlink target is rejected.
Either record, including a malformed one or a missing partner, blocks startup.
Unsafe or inaccessible namespace inspection fails closed. Moving or manually
removing records is not reconciliation or authorization to activate.
If the restored StateDir is mounted under a different container namespace, its
internal marker remains the startup hold even when the host sibling registry is
not mounted. Restores performed before this implementation, or arbitrary copied
data with no retained marker/registration, have no detectable restore lineage.

After exact archive inventory validation, restore writes and syncs the added
staging marker, then creates and syncs the external registration and its parent
directory before atomically publishing the restored target. It syncs the target
parent after publication. Registration or publication failure retains an orphan
hold; it is never automatically removed. A crash can therefore leave a blocked
unpublished target. Reserved marker/registry paths cannot be supplied by an
archive. Archived payload bytes and backup format remain unchanged.

`Control.New` and Fabric-only startup reject before opening a writable Store,
creating identities/workspaces, constructing services, or listening. Ordinary
non-restored targets retain their startup behavior. Backup of a held Hub is
rejected rather than producing an apparently ordinary archive; verification of
the original archive remains read-only and means integrity only.

`store.New` is the low-level writable maintenance primitive, not a network
startup or activation gate. Explicit offline evidence can still inspect the
restored database using immutable/read-only SQLite. Custom server construction
that bypasses the two product startup paths must supply its own hold guard.

Every writable `store.New` now acquires a nonblocking shared lock on the StateDir
directory inode before tightening permissions, creating SQLite files or migrating
schema. It retains the lock until successful database close. Control and
Fabric-only startup check both holds, acquire shared directory ownership, then
check both holds again before workspace/identity/Store/listener work. Startup
ownership overlaps the Store lease. A Control shutdown timeout retains its
Store lease; a later shutdown may finish waiting and close it. A database close
error retains uncertain ownership and remains an error on repeated close.

Offline backup and restore acquire exclusive directory ownership. Conflicting
participating writers, including an idle open Store, return an
`errors.Is(err, store.ErrStateMaintenanceBusy)` error immediately, without a
wait or automatic retry. Backup acquires before destination writes and keeps its
existing SQLite snapshot transaction. Restore verifies the archive read-only,
then establishes an empty 0700 target directory if absent. Concurrent startup
and restore creators converge on the same inode. Acquisition failure may leave
that empty directory; it never removes an existing target to make progress.
Emptiness and both holds are checked under exclusive ownership.

Restore locks both the empty target and staging directory inodes. It publishes
with a single atomic rename over the empty target, retaining both locks through
the published-inode check and target-parent fsync. There is no remove-then-rename
window. A delayed opener of the old inode, including an obsolete bind mount,
fails the held-descriptor/live-directory identity or positive-link-count check.
Constructor and pre-publication failures close their descriptors and discard only
unpublished staging; publication failure preserves all already registered holds.
No ownership lock creates an archive payload file or changes backup format 1.

This fence supports participating Hub writers on Linux filesystems that support
directory flock and atomic empty-directory replacement. Directory-only locks
allow the default non-root Hub to use `/state` without permission to write `/`;
different bind-mount paths of the same backing directory contend on the same
inode. A mounted restore target that the kernel refuses to replace fails closed,
with no unlink fallback. Existing ownership, real-directory/sticky checks and
0700 protection remain enforced; an unsafe hold registry is never repaired.
The offline operational contract still requires stopping external writers and
startup orchestration. Raw SQLite/filesystem writers, arbitrary moved/copied
state, an operator deleting both holds, hostile-owner replacement and unsupported
filesystems remain outside this fence. Lock acquisition never grants activation.

Future release requires independently authoritative current crypto/replay
watermarks, current identity/device/credential/SessionBinding epochs, retained
TLS floors and current authority proofs, and reconciliation of uncertain native,
provider and resource outcomes under trusted authorization. A verified archive,
read-only recovery status, signed old bundle or `ACTIVE` label cannot authorize
release.

The earlier paired-marker checkpoint's
[validation receipt](../.cicada-data/hub-restore-quarantine-20261004/receipt.json)
records its scoped normal/race PASS: 11 top-level tests and 12 subtests in each,
zero skips/failures, plus affected Store/Control/CLI vet PASS. Tests ran with
Go 1.27.1 in pinned image
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
network disabled and existing offline caches. The receipt preserves the first
test-fixture failure and later source/result attribution; it is not a full Go
suite run or acceptance of the clean base checkpoint alone. The final commands
were:

```sh
go test -p 2 -mod=readonly ./internal/store ./internal/control ./cmd/cicada -run '^(TestState(Backup|RestoreHold)|TestHub(Backup|RestoreHold)|TestMigrationBackup)' -count=1 -timeout=120s -json
go test -race -p 2 -mod=readonly ./internal/store ./internal/control ./cmd/cicada -run '^(TestState(Backup|RestoreHold)|TestHub(Backup|RestoreHold)|TestMigrationBackup)' -count=1 -timeout=120s -json
go vet -p 2 -mod=readonly ./internal/store ./internal/control ./cmd/cicada
```

The deterministic selectors cover source watermark advance after archive, unchanged
archived/original files, durable pre-publication hold, failed publication,
paired-marker damage, parent aliases, unsafe namespace inspection, both actual
startup constructors and ordinary startup regression. They do not demonstrate a
nonce exploit, production recovery, Native Runtime recovery or safe activation.
That receipt predates directory maintenance locking and does not validate it.

The maintenance-lock checkpoint uses a read-only clean
`857407e6f5d7d9a1ac8aa10c2db8abe726168ea0` source snapshot plus a nine-file
dirty Go overlay. Its source identity includes the full snapshot inventory,
overlay hashes and exact patch; it cannot be attributed to that HEAD alone.
Evidence is retained in the task-local
[maintenance validation receipt](/home/zyf/CICADA/.cicada-data/worktree-evidence/CICADA_restore_validation/.cicada-data/restore-validation/hub-maintenance-lock-20261004/validation-receipt.json).
Go 1.27.1 ran offline in the same pinned compiler image above, as UID 1000 with
read-only source/root filesystem and two actual bind aliases of one private
StateDir. Scoped normal PASS covers 23 top-level tests (including the subprocess
helper entry) and 18 subtests, with zero skips/failures. Scoped race PASS combines
the first attempt's three Control/four CLI tests with a successful Store-only
retry (16 top-level tests and 18 subtests). Three-package vet and Go 1.27.1
format checks also pass. All nine compiled source hashes match across those
successful checks.

The retained first normal failure establishes that `os.Rename` rejects an
existing directory before invoking the kernel; the final implementation uses
one `syscall.Rename`, with no unlink fallback. Its exact failing patch is
preserved against the same 857 baseline. The first race attempt exceeded its
120-second package timeout during modernc/schema initialization; the unchanged
Store selector passed with a 600-second timeout. Already-passed Control/CLI
race checks were retained without repetition. The final selector is:

```text
^(TestState(Maintenance|Backup|RestoreHold)|TestHub(Backup|RestoreHold)|TestMigrationBackup)
```

The bounded tests cover both process interleavings, absent/existing-empty
targets, old/new inode handoff, stale openers, actual non-root bind-mount
contention, constructor/close/shutdown failure cleanup, process death retaining
both holds, and unchanged archive key/replay bytes. This compiler-container
acceptance is separate from a disposable Hub TCP interop gate, which remains
NOT_RUN in this checkpoint. Native Runtime, model/provider, Android, physical
device, public HTTPS, production restore and safe activation remain NOT_RUN.
