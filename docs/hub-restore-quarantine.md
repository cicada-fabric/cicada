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
restored database using immutable/read-only SQLite. Callers must stop all target
writers/startup orchestration during restore, as required by the existing offline
backup/restore contract. This change does not claim concurrent startup/restore
mutual exclusion, protection against an operator deleting both records, or
protection against a hostile filesystem owner. Custom server construction that
bypasses the two product startup paths must supply its own hold guard.

Future release requires independently authoritative current crypto/replay
watermarks, current identity/device/credential/SessionBinding epochs, retained
TLS floors and current authority proofs, and reconciliation of uncertain native,
provider and resource outcomes under trusted authorization. A verified archive,
read-only recovery status, signed old bundle or `ACTIVE` label cannot authorize
release.

The [validation receipt](../.cicada-data/hub-restore-quarantine-20261004/receipt.json)
records final scoped normal/race PASS: 11 top-level tests and 12 subtests in each,
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
